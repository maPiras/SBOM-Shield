"""
core/vuldb_checker.py — VulDB integration for SBOM-Shield.

VulDB (vuldb.com) is a CVE Numbering Authority that publishes ICS/SCADA
vulnerabilities earlier than NVD and includes exploit availability data.

Pipeline roles
--------------
Phase 1e  (discovery)  — query VulDB by product name for components that
                          OSV and NVD returned nothing for.  Adds new vulns
                          including VDB-only entries (no CVE assigned yet).

Phase 2c  (enrichment) — for components that DO have vulns from other sources,
                          query VulDB to attach vdb_id and exploit_available
                          to matching CVEs without making extra per-CVE calls.

Both phases use the same single product-name query; the response is split into
"known CVEs" (enrich existing Vulnerability objects) and "new CVEs / VDB-only"
(append as new Vulnerability objects).

Authentication
--------------
Set the VULDB_API_KEY environment variable.  If absent the module returns
immediately and the pipeline continues without VulDB data.

Rate limits
-----------
VulDB uses a credit-based system with a hard cap of 30 req/min.
We sleep 2 s between requests and honour a per-scan cap (VULDB_MAX_REQUESTS)
to avoid exhausting credits on large repositories.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

VULDB_API          = "https://vuldb.com/?api"
VULDB_MAX_REQUESTS = 20      # max API calls per scan; protects credit budget
_INTER_REQUEST_S   = 2.0     # seconds between requests (30 req/min headroom)


# ── Auth ──────────────────────────────────────────────────────────────────────

def api_key() -> str | None:
    """Return the VulDB API key from the environment, or None if not set."""
    return os.environ.get("VULDB_API_KEY") or None


# ── Response parsing ──────────────────────────────────────────────────────────

@dataclass
class _VulDBEntry:
    vdb_id: str
    cve_id: str | None          # None for VDB-only (not yet assigned a CVE)
    summary: str
    cvss_score: float | None
    severity: str | None
    exploit_available: bool


def _severity_from_score(score: float) -> str:
    if score >= 9.0:   return "CRITICAL"
    if score >= 7.0:   return "HIGH"
    if score >= 4.0:   return "MEDIUM"
    return "LOW"


def _parse_entry(raw: dict) -> _VulDBEntry | None:
    """
    Parse one entry from the VulDB result list.

    VulDB response shape (with details=1):
    {
      "entry": {
        "id": "256284",
        "title": "...",
        "source": { "cve": { "id": "CVE-2024-XXXX" } },
        "cvss": {
          "score": "7.5",
          "severity": "high",
          "v3": { "score": "7.5", "severity": "high" }
        },
        "exploit": { "available": "yes" }
      }
    }
    Fields are normalised across VulDB v1/v2 response variants.
    """
    entry = raw.get("entry") or raw   # top-level key is optional in some endpoints
    if not isinstance(entry, dict):
        return None

    vdb_id = str(entry.get("id", "")).strip()
    if not vdb_id:
        return None
    vdb_id = f"VDB-{vdb_id}"

    # CVE mapping — lives under source.cve.id
    source = entry.get("source") or {}
    cve_block = source.get("cve") or {}
    cve_raw = (cve_block.get("id") or "").strip().upper()
    cve_id = cve_raw if cve_raw.startswith("CVE-") else None

    summary = (entry.get("title") or entry.get("summary") or "").strip()

    # CVSS — try v3 first, then top-level score
    cvss_score: float | None = None
    severity: str | None = None

    cvss_block = entry.get("cvss") or {}
    v3 = cvss_block.get("v3") or {}

    for src in (v3, cvss_block):
        raw_score = src.get("score") or src.get("base_score")
        if raw_score is not None:
            try:
                cvss_score = float(raw_score)
            except (TypeError, ValueError):
                pass
        raw_sev = (src.get("severity") or "").strip().upper()
        if raw_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity = raw_sev
        if cvss_score is not None:
            break

    if cvss_score is not None and severity is None:
        severity = _severity_from_score(cvss_score)

    # VulDB risk block (alternative severity source)
    if severity is None:
        risk_sev = ((entry.get("risk") or {}).get("severity") or "").strip().upper()
        if risk_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity = risk_sev

    # Exploit availability
    exploit_block = entry.get("exploit") or {}
    exploit_raw = (exploit_block.get("available") or
                   exploit_block.get("availability") or "").lower()
    exploit_available = exploit_raw in ("yes", "true", "1", "available")

    return _VulDBEntry(
        vdb_id=vdb_id,
        cve_id=cve_id,
        summary=summary,
        cvss_score=cvss_score,
        severity=severity,
        exploit_available=exploit_available,
    )


def _parse_response(payload: dict) -> list[_VulDBEntry]:
    """Extract all parseable entries from a VulDB API response payload."""
    entries: list[_VulDBEntry] = []
    result = payload.get("result") or []
    if isinstance(result, dict):
        result = [result]
    for raw in result:
        e = _parse_entry(raw)
        if e:
            entries.append(e)
    return entries


# ── API call ──────────────────────────────────────────────────────────────────

def _query_vuldb(params: dict, key: str, client: httpx.Client) -> list[_VulDBEntry]:
    """
    POST to the VulDB API and return parsed entries.
    Returns [] on any network / auth / parse error.
    """
    try:
        r = client.post(
            VULDB_API,
            data={**params, "details": "1"},
            headers={"X-VulDB-ApiKey": key},
            timeout=20.0,
        )
        r.raise_for_status()
        payload = r.json()
    except httpx.HTTPStatusError as e:
        logger.debug("VulDB HTTP %s: %s", e.response.status_code, e)
        return []
    except (httpx.RequestError, ValueError) as e:
        logger.debug("VulDB request error: %s", e)
        return []

    response_status = str((payload.get("response") or {}).get("status") or "")
    if response_status and response_status != "200":
        logger.debug("VulDB non-200 status: %s", response_status)
        return []

    return _parse_response(payload)


# ── Public entry point ────────────────────────────────────────────────────────

def enrich(results: list, client: httpx.Client) -> None:
    """
    Run VulDB Phase 1e (discovery) and Phase 2c (exploit enrichment).

    Modifies *results* (list[ScanResult]) in-place:
      - Appends new Vulnerability objects for CVEs / VDB entries not found by
        OSV or NVD.
      - Attaches vdb_id and exploit_available to existing Vulnerability objects
        whose CVE ID matches a VulDB entry.

    No-op when VULDB_API_KEY is not set.
    """
    # local import avoids circular dependency
    from core.vuln_checker import Vulnerability, _cve_id_for

    key = api_key()
    if not key:
        return

    logger.info("VulDB: API key present — starting enrichment (cap %d requests)", VULDB_MAX_REQUESTS)

    requests_made = 0

    for scan_result in results:
        if requests_made >= VULDB_MAX_REQUESTS:
            logger.info("VulDB: request cap (%d) reached — stopping", VULDB_MAX_REQUESTS)
            break

        comp = scan_result.component

        # Derive product name for the VulDB search
        name = comp.name.strip()
        if not name:
            continue

        if requests_made > 0:
            time.sleep(_INTER_REQUEST_S)

        vdb_entries = _query_vuldb({"advancedsearch": f"product:{name}"}, key, client)
        requests_made += 1

        if not vdb_entries:
            continue

        # Build lookup: CVE ID → existing Vulnerability in this ScanResult
        existing_by_cve: dict[str, object] = {}
        for v in scan_result.vulns:
            cve = _cve_id_for(v)
            if cve:
                existing_by_cve[cve] = v

        new_vulns_added = 0
        enriched = 0

        for vdb in vdb_entries:
            if vdb.cve_id and vdb.cve_id in existing_by_cve:
                # ── Phase 2c: enrich existing vuln ───────────────────────
                existing = existing_by_cve[vdb.cve_id]
                if not existing.vdb_id:
                    existing.vdb_id = vdb.vdb_id
                if vdb.exploit_available:
                    existing.exploit_available = True
                # Fill gaps OSV/NVD left blank
                if vdb.cvss_score is not None and existing.cvss_score is None:
                    existing.cvss_score = vdb.cvss_score
                if vdb.severity and not existing.severity:
                    existing.severity = vdb.severity
                enriched += 1

            else:
                # ── Phase 1e: new discovery ───────────────────────────────
                vuln_id = vdb.cve_id or vdb.vdb_id
                # Skip if this CVE ID is already known under a different alias
                if vdb.cve_id and vdb.cve_id in existing_by_cve:
                    continue

                new_vuln = Vulnerability(
                    id=vuln_id,
                    summary=vdb.summary or f"VulDB entry {vdb.vdb_id}",
                    source="VulDB",
                    severity=vdb.severity,
                    cvss_score=vdb.cvss_score,
                    vdb_id=vdb.vdb_id,
                    exploit_available=vdb.exploit_available,
                    cve_alias=vdb.cve_id if (vdb.cve_id and vuln_id != vdb.cve_id) else None,
                )
                scan_result.vulns.append(new_vuln)
                new_vulns_added += 1

        if new_vulns_added or enriched:
            logger.info(
                "VulDB [%s]: %d new, %d enriched",
                comp.name, new_vulns_added, enriched,
            )

    logger.info("VulDB: %d request(s) made", requests_made)
