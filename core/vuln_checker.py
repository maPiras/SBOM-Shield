"""
Vulnerability scanner — OSV + NVD + VulDB + CISA KEV + EPSS.

Pipeline (per scan() call)
--------------------------
Phase 0 — Parallel pre-fetch
    CISA KEV catalogue  (full JSON, ~1 MB)
    EPSS score index    (gzip CSV, ~5 MB)

Phase 1 — OSV queries  (parallel, OSV_WORKERS threads)
    For each component, POST to api.osv.dev/v1/query.
    Uses the PURL when available (most accurate); falls back to
    name + ecosystem for components without a PURL.
    Components with no version or unknown ecosystem are skipped.

Phase 1b — NVD keyword search for extended_coverage pkg:github/ components.
Phase 1c — NVD keyword search for Conan packages OSV missed.

Phase 1d — VulDB discovery + exploit enrichment  (optional, needs VULDB_API_KEY)
    Queries VulDB by product name; adds VDB-only entries and attaches
    vdb_id / exploit_available to existing vulns.

Phase 2a — CISA KEV membership  (in-memory set lookup, free)
Phase 2b — NVD enrichment  (parallel, NVD_WORKERS threads)
    For every vulnerability that has a CVE ID (directly or via OSV aliases),
    query the NVD REST API to obtain the official CVSS base score and
    severity.  If the CVE is in the CISA KEV catalogue, the source field
    is overwritten to "CISA-KEV" to flag active exploitation.

Phase 3 — EPSS enrichment  (in-memory, no network)
    Attach EPSS probability scores from the pre-loaded index.

Concurrency notes
-----------------
OSV has no documented rate limit → 10 parallel workers are safe.
NVD allows ~5 req/30 s without an API key → 3 workers to stay conservative.
"""
import logging
import math
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import httpx

from .sbom_parser import Component, ECOSYSTEM_MAP
from .epss_checker import load_epss_index, enrich_with_epss

logger = logging.getLogger(__name__)

OSV_API      = "https://api.osv.dev/v1/query"
CISA_KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_API  = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Canonical ordering used for sorting and verdict logic (most severe first)
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

OSV_WORKERS = 10   # OSV has no documented rate limit

# NVD API key (optional). With a key NVD allows ~50 req/30 s vs ~5 req/30 s
# without one — the keyless limit is what made the benchmark unstable (503s +
# read timeouts corrupting late repos). When a key is present we widen the
# worker pool and shrink the inter-request delay accordingly.
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()
NVD_WORKERS = 8 if NVD_API_KEY else 3
_NVD_KEYWORD_DELAY = 0.7 if NVD_API_KEY else 6   # seconds between sequential keyword queries

# HTTP status codes worth retrying on for NVD: rate-limit (429) plus transient
# server errors (502/503/504). The keyless benchmark hit ~39 NVD 503s that the
# old 429-only retry let through, silently zeroing late repos' CVE counts.
_NVD_RETRY_CODES = frozenset({429, 502, 503, 504})

# High-CVE, keyword-routed C libraries whose NVD keyword search returns ALL
# historical CVEs when no version is known (openssl alone → ~546, back to
# CVE-2003-0545). When these are detected by a bare include with no recovered
# version, the keyword search is skipped so a linked (non-vendored) copy does
# not flood the report. They remain in the component DB, signature pack and the
# SC3 coverage tally — only their version-less vuln lookup is suppressed. Same
# precision rationale as the unregistered detect_plc_scada. Matched on the
# canonical _PURL_MAP display name, lower-cased.
_VERSION_ANCHORED_KEYWORD_LIBS = frozenset({"openssl", "wolfssl", "zlib"})

# Libraries whose NVD keyword route is unreliable regardless of version and are
# therefore never keyword-searched. qt is the case: its single umbrella CPE
# (cpe:2.3:a:qt:qt) is module-blind so version filtering cannot narrow it, AND
# the bare keyword "qt" collides with QNAP "QTS" advisories — pulling in unrelated
# QNAP CVEs (several KEV-listed → spurious Act findings). The monolithic-framework
# decomposition is documented future work; until then qt's keyword lookup is off.
_KEYWORD_UNRELIABLE_LIBS = frozenset({"qt"})


@dataclass
class Vulnerability:
    """A single vulnerability entry as returned by OSV and enriched by NVD/KEV/EPSS."""
    id: str
    summary: str
    source: str = "OSV"              # "OSV" | "NVD" | "CISA-KEV"
    severity: str | None = None      # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    cvss_score: float | None = None
    fixed_version: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    # CVE ID extracted from OSV aliases[] for GHSA/PYSEC entries that have one.
    # Required for NVD/KEV lookups when the primary ID is not a CVE.
    cve_alias: str | None = None
    # Affected version range from NVD CPE configurations.
    # Populated by _fetch_nvd_direct; used for client-side filtering when the
    # component has a known version, and for display when it doesn't.
    affects_from: str | None = None   # versionStartIncluding
    affects_before: str | None = None # versionEndExcluding
    version_confirmed: bool = False   # True when component version falls in range
    # VulDB-specific fields — populated by Phase 1d/2c when VULDB_API_KEY is set
    vdb_id: str | None = None              # VDB-XXXXXX identifier
    exploit_available: bool = False        # VulDB reports a public exploit exists


@dataclass
class ScanResult:
    """Aggregated vulnerability data for a single Component."""
    component: Component
    vulns: list[Vulnerability] = field(default_factory=list)
    error: str | None = None   # non-None means the component was skipped

    @property
    def is_vulnerable(self):
        return bool(self.vulns)

    @property
    def highest_severity(self):
        """Return the most severe level found across all vulns, or None."""
        found = {v.severity for v in self.vulns if v.severity}
        for sev in SEVERITY_ORDER:
            if sev in found:
                return sev
        return None

    @property
    def max_cvss(self):
        scores = [v.cvss_score for v in self.vulns if v.cvss_score]
        return max(scores) if scores else None

    @property
    def max_epss(self):
        scores = [v.epss_score for v in self.vulns if v.epss_score is not None]
        return max(scores) if scores else None


# ─── CVSS v3.x base score calculation ────────────────────────────────────────

def _cvss_vector_to_score(vector: str) -> float | None:
    """
    Compute the CVSS v3.0/3.1 base score from a vector string.

    OSV GHSA entries sometimes carry a CVSS vector but no numeric score.
    This avoids an extra NVD round-trip for those entries.
    Returns None if the vector is malformed or missing required components.
    """
    try:
        if "/" in vector:
            vector = vector.split("/", 1)[1]   # strip "CVSS:3.1/" prefix
        parts = dict(p.split(":") for p in vector.split("/"))

        AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[parts["AV"]]
        AC  = {"L": 0.77, "H": 0.44}[parts["AC"]]
        scope_changed = parts.get("S") == "C"
        PR  = {"N": 0.85,
               "L": 0.68 if scope_changed else 0.62,
               "H": 0.50 if scope_changed else 0.27}[parts["PR"]]
        UI  = {"N": 0.85, "R": 0.62}[parts["UI"]]
        S   = parts["S"]
        C   = {"N": 0.00, "L": 0.22, "H": 0.56}[parts["C"]]
        I   = {"N": 0.00, "L": 0.22, "H": 0.56}[parts["I"]]
        A   = {"N": 0.00, "L": 0.22, "H": 0.56}[parts["A"]]

        ISS = 1 - (1 - C) * (1 - I) * (1 - A)
        if S == "U":
            impact = 6.42 * ISS
        else:
            # Scope Changed formula (CVSS 3.1 §7.3)
            impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02) ** 15

        exploitability = 8.22 * AV * AC * PR * UI

        if impact <= 0:
            return 0.0

        base = (min(impact + exploitability, 10) if S == "U"
                else min(1.08 * (impact + exploitability), 10))

        # CVSS mandates ceiling rounding to one decimal place
        return math.ceil(base * 10) / 10

    except (KeyError, ValueError, ZeroDivisionError):
        return None


# ─── OSV response parsing ─────────────────────────────────────────────────────

def _parse_vuln(data: dict) -> Vulnerability:
    """
    Convert a raw OSV vulnerability dict into a Vulnerability object.

    Severity extraction priority:
      1. database_specific.severity  (GitHub Advisories)
      2. database_specific.cvss_v3_score  (numeric)
      3. ecosystem_specific.cvss_v3_score  (some ecosystems)
      4. Compute from the CVSS vector in severity[]  (fallback)
    If CVSS >= 9.0 and no textual severity is present, we derive it from
    the score to avoid leaving vulns with severity=None.
    """
    summary = data.get("summary") or data.get("details", "")[:200]

    db = data.get("database_specific", {})
    _sev_raw = db.get("severity", "").upper()
    _sev_map = {"MODERATE": "MEDIUM", "CRITICAL": "CRITICAL",
                "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    severity = _sev_map.get(_sev_raw) or None

    cvss_score = db.get("cvss_v3_score") or db.get("cvss")
    if cvss_score is None:
        es = data.get("ecosystem_specific", {})
        cvss_score = es.get("cvss_v3_score") or es.get("cvss")

    # Compute score from vector when no numeric score is available
    if cvss_score is None:
        for sev_entry in data.get("severity", []):
            score = _cvss_vector_to_score(sev_entry.get("score", ""))
            if score is not None:
                cvss_score = score
                break

    if isinstance(cvss_score, (int, float)):
        cvss_score = float(cvss_score)
        # Derive textual severity from CVSS if not already set
        if not severity:
            if cvss_score >= 9.0:   severity = "CRITICAL"
            elif cvss_score >= 7.0: severity = "HIGH"
            elif cvss_score >= 4.0: severity = "MEDIUM"
            else:                   severity = "LOW"

    # Extract the fixed version from the first affected range that has one
    fixed = None
    for affected in data.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed = event["fixed"]
                    break

    vuln_id = data.get("id", "UNKNOWN")

    # Store the CVE alias for non-CVE IDs (GHSA-…, PYSEC-…) so downstream
    # NVD/KEV lookups can find the right record
    cve_alias = None
    if not vuln_id.upper().startswith("CVE-"):
        for alias in data.get("aliases", []):
            if alias.upper().startswith("CVE-"):
                cve_alias = alias.upper()
                break

    return Vulnerability(
        id=vuln_id, summary=summary, source="OSV",
        severity=severity, cvss_score=cvss_score,
        fixed_version=fixed, cve_alias=cve_alias,
    )


# ─── CISA KEV loader ──────────────────────────────────────────────────────────

def _load_kev_index(client: httpx.Client) -> set[str]:
    """
    Fetch the CISA Known Exploited Vulnerabilities catalogue.

    Returns a set of CVE IDs (uppercase).  An empty set is returned on any
    error so the rest of the pipeline continues without KEV context.
    """
    try:
        r = client.get(CISA_KEV_API, timeout=20.0)
        r.raise_for_status()
        items = r.json().get("vulnerabilities", [])
        return {
            str(item.get("cveID", "")).strip().upper()
            for item in items
            if item.get("cveID")
        }
    except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as e:
        logger.debug(f"Could not load CISA KEV catalogue: {e}")
        return set()


# ─── NVD enrichment ───────────────────────────────────────────────────────────

def _query_nvd(cve_id: str, client: httpx.Client) -> dict | None:
    """
    Fetch CVSS score and severity for *cve_id* from the NVD REST API v2.

    Tries CVSS v3.1 first, then v3.0, then v2 (legacy).
    Retries up to 2 times on HTTP 429 with exponential backoff.
    Returns None on any network or parse error.
    """
    import time as _time

    for attempt in range(4):
        try:
            r = client.get(NVD_CVE_API, params={"cveId": cve_id}, timeout=30.0)
            r.raise_for_status()
            payload = r.json()
            break
        except httpx.HTTPStatusError as e:
            if e.response.status_code in _NVD_RETRY_CODES and attempt < 3:
                _time.sleep((attempt + 1) * 10)
                continue
            return None
        except httpx.RequestError:
            # Timeouts / connection drops are transient under NVD load — retry.
            if attempt < 3:
                _time.sleep((attempt + 1) * 10)
                continue
            return None
        except ValueError:
            return None
    else:
        return None

    entries = payload.get("vulnerabilities", [])
    if not entries:
        return None

    cve = entries[0].get("cve", {})
    descriptions = cve.get("descriptions", [])
    summary = next(
        (d.get("value") for d in descriptions if d.get("lang") == "en" and d.get("value")),
        None,
    )

    cvss_score = None
    severity   = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {})
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss_data = m.get("cvssData", {})
            score = cvss_data.get("baseScore")
            if isinstance(score, (int, float)):
                cvss_score = float(score)
            severity = (cvss_data.get("baseSeverity")
                        or m.get("baseSeverity")
                        or severity)
            break

    return {
        "summary":    summary,
        "cvss_score": cvss_score,
        "severity":   severity.upper() if isinstance(severity, str) and severity else None,
    }


def _cve_id_for(vuln: Vulnerability) -> str | None:
    """Return the CVE ID associated with *vuln* (direct or via alias), or None."""
    vid = vuln.id.strip().upper()
    if vid.startswith("CVE-"):
        return vid
    if vuln.cve_alias:
        return vuln.cve_alias.strip().upper()
    return None


def _apply_kev(vuln: Vulnerability, kev_index: set[str]) -> None:
    """
    Mark *vuln* as CISA-KEV-sourced if its CVE is in the catalogue.

    In-memory set lookup — safe to run for every vuln with no rate-limit cost.
    """
    cve_id = _cve_id_for(vuln)
    if cve_id and cve_id in kev_index:
        vuln.source = "CISA-KEV"


def _enrich_nvd(vuln: Vulnerability, client: httpx.Client) -> None:
    """
    Fetch CVSS score / severity / description from NVD for a single vuln.

    Only called for vulns that still lack a CVSS score or severity after
    OSV parsing and Phase 1b NVD direct search.  Vulns already enriched
    (notably the Phase 1b results whose source is already "NVD" with a
    populated score) are never re-queried — this is the key fix that keeps
    us under NVD's 5 req / 30 s rate limit.
    """
    cve_id = _cve_id_for(vuln)
    if not cve_id:
        return

    nvd = _query_nvd(cve_id, client)
    if not nvd:
        return

    # Don't downgrade a CISA-KEV source back to NVD
    if vuln.source != "CISA-KEV":
        vuln.source = "NVD"
    if nvd.get("summary") and not vuln.summary:
        vuln.summary = nvd["summary"]
    if nvd.get("severity") and not vuln.severity:
        vuln.severity = nvd["severity"]
    if nvd.get("cvss_score") is not None and vuln.cvss_score is None:
        vuln.cvss_score = nvd["cvss_score"]


def _apply_severity_default(vuln: Vulnerability) -> None:
    """
    Fall back to UNKNOWN severity when neither OSV nor NVD could provide one.

    UNKNOWN triggers a WARN verdict rather than being silently ignored,
    ensuring that unscored vulnerabilities remain visible in the report.
    """
    if vuln.severity is None:
        vuln.severity = "UNKNOWN"


# ─── OSV query ────────────────────────────────────────────────────────────────

def _fetch_osv(component: Component, client: httpx.Client) -> ScanResult:
    """
    Query OSV for a single component.  NVD enrichment is done separately.

    Query strategy:
      - PURL available → use it directly (most accurate, works for any ecosystem)
      - No PURL → use name + ecosystem (requires ecosystem to be in ECOSYSTEM_MAP)
    Components without a version or with an unknown ecosystem are skipped
    and recorded with an explanatory error string.
    """
    result = ScanResult(component=component)

    # Skip only when we have neither a version nor a PURL.
    # A bare PURL query (no version) is valid for OSV and returns all
    # known advisories for the package — useful for OT components whose
    # version we cannot extract from the source tree.
    if not component.version and not component.purl:
        result.error = "no version"
        return result

    if component.purl:
        payload = {"package": {"purl": component.purl}}
    else:
        ecosystem = ECOSYSTEM_MAP.get(component.ecosystem or "")
        if not ecosystem:
            result.error = f"unknown ecosystem: {component.ecosystem}"
            return result
        payload = {
            "package": {"name": component.name, "ecosystem": ecosystem},
            "version": component.version,
        }

    try:
        r = client.post(OSV_API, json=payload, timeout=15.0)
        r.raise_for_status()
        for v in r.json().get("vulns", []):
            result.vulns.append(_parse_vuln(v))
    except httpx.HTTPStatusError as e:
        result.error = f"HTTP {e.response.status_code}"
    except httpx.RequestError as e:
        result.error = f"network error: {e}"

    return result


# ─── NVD CPE version-range extraction ────────────────────────────────────────

def _parse_version_tuple(v: str) -> tuple[int, ...]:
    """Convert '3.5.17.0' → (3, 5, 17, 0) for comparison."""
    parts = []
    for seg in v.split("."):
        try:
            parts.append(int(seg))
        except ValueError:
            break
    return tuple(parts) or (0,)


def _version_in_range(
    ver: str,
    start_incl: str | None,
    end_excl: str | None,
    end_incl: str | None = None,
) -> bool:
    """Check if *ver* falls within an NVD CPE affected range."""
    v = _parse_version_tuple(ver)
    if start_incl and v < _parse_version_tuple(start_incl):
        return False
    if end_excl and v >= _parse_version_tuple(end_excl):
        return False
    if end_incl and v > _parse_version_tuple(end_incl):
        return False
    return True


def _extract_cpe_range(cve: dict) -> tuple[str | None, str | None]:
    """
    Extract the broadest affected version range from NVD CPE configurations.

    Walks all cpeMatch entries marked vulnerable=True and returns the widest
    (lowest versionStartIncluding, highest versionEndExcluding) across all
    matches.  Returns (None, None) when no version bounds are present.
    """
    starts: list[str] = []
    ends:   list[str] = []

    for node in cve.get("configurations", []):
        for match in node.get("nodes", []):
            for cpe in match.get("cpeMatch", []):
                if not cpe.get("vulnerable", False):
                    continue
                s = cpe.get("versionStartIncluding")
                e = cpe.get("versionEndExcluding") or cpe.get("versionEndIncluding")
                if s:
                    starts.append(s)
                if e:
                    ends.append(e)

    lowest_start = min(starts, key=_parse_version_tuple) if starts else None
    highest_end  = max(ends,   key=_parse_version_tuple) if ends   else None
    return lowest_start, highest_end


# ─── NVD direct keyword search ────────────────────────────────────────────────
# OSV indexes package-ecosystem CVEs (PyPI, npm, Go …) but does NOT index
# C/C++ GitHub-hosted projects.  OT components like libmodbus, open62541,
# OpenPLC, FreeRTOS all have CVEs in NVD only.  This function supplements
# the OSV phase for any component whose PURL is pkg:github/.

def _nvd_product_name(purl: str) -> str | None:
    """
    Extract the NVD keyword to search from a PURL.

    Supports:
      pkg:github/thiagoralves/OpenPLC_v3   → "OpenPLC_v3"
      pkg:github/stephane/libmodbus        → "libmodbus"
      pkg:conan/qt                         → "qt"
      pkg:conan/msgpack-cxx                → "msgpack-cxx"

    Returns None if the PURL can't be parsed.
    """
    try:
        # Strip optional @version suffix
        base = purl.split("@")[0]
        if "github/" in base:
            path = base.split("github/", 1)[1]
            return path.split("/")[-1]          # take repo name, drop owner
        if "conan/" in base:
            path = base.split("conan/", 1)[1]
            return path.split("/")[-1]          # package name (no namespace in conan)
        return None
    except (IndexError, ValueError):
        return None


def _fetch_nvd_direct(component: Component, client: httpx.Client) -> ScanResult:
    """
    Search NVD by keyword for an extended_coverage-injected component.

    Called for extended_coverage-injected components whose PURL is pkg:github/
    — an ecosystem not indexed by OSV.

    NVD keyword search is broad; we rely on the product name being
    distinctive enough (e.g. "libmodbus", "OpenPLC_v3").

    Version-aware filtering:
      - When the component has a known version, CVEs whose CPE configuration
        range does not include that version are dropped (confirmed=True on hits).
      - When no version is known, all CVEs are kept but each carries its
        affects_from / affects_before range for display in the report.

    Retries up to 3 times on HTTP 429 (NVD rate limit) with exponential backoff.
    """
    import time

    result = ScanResult(component=component)

    keyword = _nvd_product_name(component.purl or "")
    if not keyword:
        result.error = "cannot derive NVD keyword from PURL"
        return result

    entries = []
    for attempt in range(4):
        try:
            r = client.get(NVD_CVE_API, params={"keywordSearch": keyword}, timeout=45.0)
            r.raise_for_status()
            entries = r.json().get("vulnerabilities", [])
            break
        except httpx.HTTPStatusError as e:
            if e.response.status_code in _NVD_RETRY_CODES and attempt < 3:
                wait = (attempt + 1) * 10     # 10s, 20s, 30s
                logger.debug("NVD %s for %s — retrying in %ds",
                             e.response.status_code, keyword, wait)
                time.sleep(wait)
                continue
            result.error = f"NVD direct: {e}"
            return result
        except httpx.RequestError as e:
            # Timeouts / connection drops are transient under NVD load — retry
            # so a slow response does not silently zero this component's CVEs.
            if attempt < 3:
                wait = (attempt + 1) * 10
                logger.debug("NVD timeout/conn for %s — retrying in %ds", keyword, wait)
                time.sleep(wait)
                continue
            result.error = f"NVD direct: {e}"
            return result
        except ValueError as e:
            result.error = f"NVD direct: {e}"
            return result

    comp_ver = component.version or ""
    has_version = bool(comp_ver)

    for entry in entries:
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        # ── Extract affected version range from CPE configurations ───────
        affects_from, affects_before = _extract_cpe_range(entry)

        # ── Version-based filtering ──────────────────────────────────────
        # When we know the component version AND the CVE has version bounds,
        # skip CVEs that don't affect this specific version.
        confirmed = False
        if has_version and (affects_from or affects_before):
            if not _version_in_range(comp_ver, affects_from, affects_before):
                continue  # version is outside affected range — skip
            confirmed = True

        # ── Extract CVSS score and severity ──────────────────────────────
        descriptions = cve.get("descriptions", [])
        summary = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "",
        )

        cvss_score = None
        severity   = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {})
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_data = m.get("cvssData", {})
                score = cvss_data.get("baseScore")
                if isinstance(score, (int, float)):
                    cvss_score = float(score)
                severity = cvss_data.get("baseSeverity") or m.get("baseSeverity") or severity
                break

        result.vulns.append(Vulnerability(
            id=cve_id,
            summary=summary,
            source="NVD",
            severity=severity.upper() if isinstance(severity, str) else None,
            cvss_score=cvss_score,
            affects_from=affects_from,
            affects_before=affects_before,
            version_confirmed=confirmed,
        ))

    return result


# ─── Public entry point ───────────────────────────────────────────────────────

def scan(components: list[Component]) -> list[ScanResult]:
    """
    Run the full vulnerability scan pipeline on a list of components.

    Returns one ScanResult per input component, in the same order.
    Results for skipped components (no version, unknown ecosystem) have
    is_vulnerable=False and a non-None error string.
    """
    _headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    with httpx.Client(headers=_headers) as client:

        # Phase 0 — download KEV + EPSS in parallel (independent HTTP fetches)
        with ThreadPoolExecutor(max_workers=2) as pool:
            kev_fut  = pool.submit(_load_kev_index, client)
            epss_fut = pool.submit(load_epss_index, client)
            kev_index  = kev_fut.result()
            epss_index = epss_fut.result()

        # Phase 1 — OSV queries in parallel; original order is preserved
        logger.info(f"Querying OSV for {len(components)} components ({OSV_WORKERS} workers)…")
        ordered: list[ScanResult | None] = [None] * len(components)
        with ThreadPoolExecutor(max_workers=OSV_WORKERS) as pool:
            future_to_idx = {
                pool.submit(_fetch_osv, c, client): i
                for i, c in enumerate(components)
            }
            for fut in as_completed(future_to_idx):
                ordered[future_to_idx[fut]] = fut.result()
        results: list[ScanResult] = [r for r in ordered if r is not None]

        # Phase 1b — NVD direct keyword search for extended_coverage-injected pkg:github/ components.
        # OSV has no index for C/C++ GitHub repos (OT libraries, RTOS, PLC runtimes).
        # We run a targeted NVD keyword search ONLY for components injected by the
        # OT enrichment layer — not for all pkg:github/ entries (Syft picks up
        # GitHub Actions which would flood the NVD rate limit for no benefit).
        def _keyword_skip(c):
            """Return a skip-reason string if this component's NVD keyword search
            should be suppressed, else None. Covers two failure modes:
              • qt and friends — keyword route unreliable at any version.
              • openssl/wolfssl/zlib with no version — keyword returns every
                historical CVE for the name."""
            nm = c.name.lower()
            if nm in _KEYWORD_UNRELIABLE_LIBS:
                return ("keyword-unreliable: monolithic/collision-prone PURL, "
                        "keyword search skipped")
            if nm in _VERSION_ANCHORED_KEYWORD_LIBS and not (c.version or "").strip():
                return "version-anchored: no version recovered, keyword search skipped"
            return None

        github_targets = [
            r for r in results
            if not r.vulns
            and r.component.extended_injected
            and r.component.purl
            and r.component.purl.startswith("pkg:github/")
            and not _keyword_skip(r.component)
        ]
        # Record suppressions so they are visible in the report rather than
        # looking like silent misses, and so Phase 1c (which filters on r.error)
        # also skips them. Overrides any benign OSV "no version" error for these.
        # NOTE: filtered on _keyword_skip above (NOT r.error) so version-less
        # keyword libs like mbedtls/threadx — which also carry "no version" — are
        # still searched here.
        for r in results:
            if not r.vulns:
                reason = _keyword_skip(r.component)
                if reason:
                    r.error = reason
        if github_targets:
            import time as _time
            logger.info(
                f"Phase 1b: NVD keyword search for {len(github_targets)} "
                f"OT component(s)…"
            )
            # Run sequentially with a small delay between requests to stay
            # within NVD's rate limit (~5 req/30 s without an API key).
            for i, orig in enumerate(github_targets):
                if i > 0:
                    _time.sleep(_NVD_KEYWORD_DELAY)
                nvd = _fetch_nvd_direct(orig.component, client)
                if nvd.vulns:
                    orig.vulns  = nvd.vulns
                    orig.error  = None
                    logger.info(
                        f"NVD direct [{orig.component.name}]: "
                        f"{len(nvd.vulns)} CVE(s)"
                    )
                elif nvd.error:
                    orig.error = nvd.error

        # Phase 1c — NVD keyword search for Conan packages that OSV missed.
        # OSV's ConanCenter index is incomplete: public C++ packages (Qt,
        # breakpad, msgpack-cxx, …) often have NVD entries even when OSV
        # returns nothing.  Private vendor packages (art-adp-*, artsdk-*)
        # will naturally return 0 NVD hits, so they add only a small delay.
        conan_targets = [
            r for r in results
            if not r.vulns
            and not r.error
            and r.component.purl
            and r.component.purl.startswith("pkg:conan/")
        ]
        if conan_targets:
            import time as _time
            logger.info(
                f"Phase 1c: NVD keyword search for {len(conan_targets)} "
                f"conan component(s)…"
            )
            for i, orig in enumerate(conan_targets):
                if i > 0:
                    _time.sleep(_NVD_KEYWORD_DELAY)
                nvd = _fetch_nvd_direct(orig.component, client)
                if nvd.vulns:
                    orig.vulns = nvd.vulns
                    orig.error = None
                    logger.info(
                        f"NVD direct [{orig.component.name}]: "
                        f"{len(nvd.vulns)} CVE(s)"
                    )
                elif nvd.error:
                    orig.error = nvd.error

        # Phase 1d — VulDB discovery + exploit enrichment
        # Queries VulDB by product name for each component.  New CVEs and
        # VDB-only entries are injected into existing ScanResults; known CVEs
        # get vdb_id and exploit_available attached without extra API calls.
        # Skipped when VULDB_API_KEY is not set in the environment.
        from core.vuldb_checker import enrich as vuldb_enrich, api_key as _vuldb_key
        if _vuldb_key():
            vuldb_enrich(results, client)

        # Phase 2a — CISA KEV membership (in-memory set lookup, free)
        # Applied to every CVE-bearing vuln so KEV flags are never missed.
        if kev_index:
            for r in results:
                if r.is_vulnerable:
                    for v in r.vulns:
                        _apply_kev(v, kev_index)

        # Phase 2b — NVD enrichment (rate-limited, network)
        # Only query NVD for vulns that still lack a CVSS score or severity.
        # Phase 1b already populated NVD data for OT github-hosted components,
        # so re-querying them would waste ~85 requests and blow the rate limit.
        vulns_to_enrich = [
            v for r in results if r.is_vulnerable
            for v in r.vulns
            if (v.cvss_score is None or v.severity is None)
            and _cve_id_for(v) is not None
        ]
        if vulns_to_enrich:
            logger.info(
                f"Enriching {len(vulns_to_enrich)} vulns via NVD "
                f"({NVD_WORKERS} workers)…"
            )
            with ThreadPoolExecutor(max_workers=NVD_WORKERS) as pool:
                futs = [pool.submit(_enrich_nvd, v, client)
                        for v in vulns_to_enrich]
                for fut in as_completed(futs):
                    fut.result()

        # Phase 3 — EPSS enrichment (in-memory, no network)
        for r in results:
            if r.is_vulnerable:
                enrich_with_epss(r.vulns, epss_index)

    # Apply severity defaults and log a summary line per vulnerable component
    for r in results:
        for v in r.vulns:
            _apply_severity_default(v)
        if r.is_vulnerable:
            logger.warning(f"  ⚠ {r.component.name}: {len(r.vulns)} vuln(s) [{r.highest_severity}]")
        elif r.error:
            logger.debug(f"  skipped {r.component.name}: {r.error}")

    return results
