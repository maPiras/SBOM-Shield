"""
CSAF feed loaders — Siemens ProductCERT + CISA ICS-CERT.

Each feed exposes:
    name:        publisher tag stored on records
    list_documents(max_docs=None) -> Iterator[(url, doc_json)]

Both feeds publish a JSON index of advisory URLs. We deliberately do NOT
implement full ROLIE Atom — the JSON listings are enough and stable.

Concurrency: parallel fetch via ThreadPoolExecutor (8 workers). Each
document fetch is a single GET + JSON parse.
"""
from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterator

import httpx

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = 30.0
_WORKERS      = 8


def _http_json(url: str) -> dict | None:
    try:
        r = httpx.get(url, timeout=_HTTP_TIMEOUT, follow_redirects=True,
                      headers={"User-Agent": "SBOM-Shield/csaf 1.0"})
        if r.status_code != 200:
            return None
        return r.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        logger.debug(f"fetch failed {url}: {exc}")
        return None


# ─── Siemens ProductCERT ─────────────────────────────────────────────────────

class SiemensFeed:
    """CSAF Trusted Provider — discovered via provider-metadata.json.

    Fetch path: ROLIE feed → entries[].link[rel='self'].href → CSAF doc.
    """
    name = "Siemens"
    rolie_url = "https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json"

    def _list_urls(self, max_docs: int | None) -> list[str]:
        feed_doc = _http_json(self.rolie_url)
        if not feed_doc:
            logger.error("Siemens ROLIE feed fetch failed")
            return []
        entries = (feed_doc.get("feed") or {}).get("entry") or []
        urls: list[str] = []
        for e in entries:
            for link in e.get("link", []) or []:
                if link.get("rel") == "self" and link.get("href"):
                    urls.append(link["href"])
                    break
        # Most-recent first — entries are roughly ordered by published date
        # but the IDs (ssa-NNNNNN) are monotonic, so sort by URL desc as a
        # cheap proxy for "newest first".
        urls.sort(reverse=True)
        if max_docs:
            urls = urls[:max_docs]
        return urls

    def list_documents(self, max_docs: int | None = None) -> Iterator[tuple[str, dict]]:
        urls = self._list_urls(max_docs)
        logger.info(f"[Siemens] {len(urls)} advisories listed (limit={max_docs})")
        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            futures = {pool.submit(_http_json, u): u for u in urls}
            for fut in as_completed(futures):
                url = futures[fut]
                doc = fut.result()
                if doc:
                    yield url, doc


# ─── CISA ICS-CERT ───────────────────────────────────────────────────────────

class CisaIcsFeed:
    """CISA publishes CSAF on github.com/cisagov/CSAF (branch: develop).

    Directory layout:
        csaf_files/OT/white/{YYYY}/icsa-YY-NNN-NN.json
        csaf_files/IT/white/{YYYY}/...

    We pull from the GitHub Contents API to get the listing (no auth needed
    for public repos, 60 req/hr unauth — well within our scan budget).
    """
    name = "CISA"
    api_template  = "https://api.github.com/repos/cisagov/CSAF/contents/csaf_files/OT/white/{year}?ref=develop"

    def __init__(self, years: list[int] | None = None):
        from datetime import datetime
        cur = datetime.now().year
        self.years = years or [cur, cur - 1]

    def _list_urls_for_year(self, year: int) -> list[str]:
        url = self.api_template.format(year=year)
        try:
            r = httpx.get(url, timeout=_HTTP_TIMEOUT, follow_redirects=True,
                          headers={"User-Agent": "SBOM-Shield/csaf 1.0",
                                   "Accept": "application/vnd.github+json"})
            if r.status_code != 200:
                logger.warning(f"[CISA] year={year} listing status {r.status_code}")
                return []
            entries = r.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            logger.error(f"[CISA] listing year={year} failed: {exc}")
            return []
        return [e["download_url"] for e in entries
                if e.get("type") == "file" and (e.get("name") or "").endswith(".json")
                and e.get("download_url")]

    def list_documents(self, max_docs: int | None = None) -> Iterator[tuple[str, dict]]:
        all_urls: list[str] = []
        for year in self.years:
            urls = self._list_urls_for_year(year)
            logger.info(f"[CISA] year={year}: {len(urls)} advisories")
            all_urls.extend(urls)
        # Newest-first cheap proxy: icsa-26-... > icsa-25-...
        all_urls.sort(reverse=True)
        if max_docs:
            all_urls = all_urls[:max_docs]
        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            futures = {pool.submit(_http_json, u): u for u in all_urls}
            for fut in as_completed(futures):
                url = futures[fut]
                doc = fut.result()
                if doc:
                    yield url, doc


# ─── Registry ────────────────────────────────────────────────────────────────

FEEDS = {
    "siemens": SiemensFeed,
    "cisa":    CisaIcsFeed,
}


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
def looks_like_cve(s: str | None) -> bool:
    return bool(s and _CVE_RE.fullmatch(s))
