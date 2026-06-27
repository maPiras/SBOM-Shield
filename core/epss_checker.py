"""
EPSS (Exploit Prediction Scoring System) enrichment.

EPSS is a daily-updated probability score (0–1) published by FIRST that
estimates the likelihood a CVE will be exploited in the wild within the next
30 days.  Scores >= EPSS_ESCALATION_THRESHOLD cause the pipeline verdict to
be escalated to FAIL regardless of CVSS severity, because a MEDIUM-severity
vuln that is actively being exploited is more dangerous than a CRITICAL one
that isn't.

Data source
-----------
FIRST publishes a gzip-compressed CSV at a stable URL.  The file is ~5 MB
and contains one row per CVE: (cve_id, epss_score, percentile).
The entire index is loaded into memory once per scan run and kept as a dict
for O(1) lookups during per-vulnerability enrichment.

Reference: https://www.first.org/epss/
"""
import csv
import gzip
import io
import logging

import httpx

logger = logging.getLogger(__name__)

EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

# CVEs with EPSS >= this threshold are escalated to FAIL even when CVSS is
# MEDIUM or LOW.  0.5 = top-50th percentile of exploitability probability.
EPSS_ESCALATION_THRESHOLD = 0.5


def load_epss_index(client: httpx.Client) -> dict[str, tuple[float, float]]:
    """
    Download the current EPSS dataset and return an in-memory index.

    Returns
    -------
    dict mapping CVE-ID (uppercase) → (epss_score, percentile).
    Returns an empty dict on any network or parse error — callers treat
    missing EPSS data as a non-fatal enrichment gap.
    """
    try:
        r = client.get(EPSS_CSV_URL, timeout=60.0, follow_redirects=True)
        r.raise_for_status()

        # The CSV is gzip-compressed; decompress in-memory to avoid disk I/O
        with gzip.open(io.BytesIO(r.content), "rt") as f:
            reader = csv.reader(f)
            index: dict[str, tuple[float, float]] = {}
            for row in reader:
                # Skip comment lines (start with #) and the header row
                if not row or row[0].startswith("#"):
                    continue
                if row[0].strip().lower() == "cve":
                    continue
                cve_id = row[0].strip().upper()
                try:
                    index[cve_id] = (float(row[1]), float(row[2]))
                except (ValueError, IndexError):
                    continue  # malformed row — skip silently

        logger.info(f"EPSS index loaded: {len(index):,} entries")
        return index

    except Exception as e:
        logger.warning(f"Could not load EPSS data: {e}")
        return {}


def enrich_with_epss(
    vulns: list,
    epss_index: dict[str, tuple[float, float]],
) -> None:
    """
    Attach epss_score and epss_percentile to each Vulnerability in-place.

    Lookup strategy (first match wins):
      1. Primary vulnerability ID  (e.g. CVE-2021-44228 or GHSA-…)
      2. CVE alias stored on the vuln object  (extracted from OSV aliases[])
         This handles GHSA/PYSEC entries that have an associated CVE ID.

    No-op for vulns whose ID is not in the EPSS index (e.g. advisories that
    have no CVE, or CVEs too new to be in today's snapshot).
    """
    for vuln in vulns:
        for lookup in (vuln.id.strip().upper(), getattr(vuln, "cve_alias", None)):
            if lookup and lookup in epss_index:
                vuln.epss_score, vuln.epss_percentile = epss_index[lookup]
                break
