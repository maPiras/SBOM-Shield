"""
CSAF integration — public entry points.

Usage from a script:

    from core.csaf import refresh, get_for_cves

    refresh(feed="siemens", max_docs=200)     # one-shot fetch + cache upsert
    advisories = get_for_cves(["CVE-2024-..."])

The cache lives in storage/scans.db (table csaf_advisories) and survives
across runs. refresh() is idempotent — re-running is safe and cheap.
"""
from __future__ import annotations

import logging
from typing import Iterable

from . import feeds as _feeds
from . import parser as _parser
from . import storage as _storage

logger = logging.getLogger(__name__)


def init() -> None:
    _storage.init_schema()


def refresh(feed: str = "siemens", max_docs: int | None = None) -> dict:
    """Fetch one feed and upsert all parsed records.

    Returns {documents_fetched, records_written, errors}."""
    init()
    cls = _feeds.FEEDS.get(feed)
    if not cls:
        raise ValueError(f"unknown feed {feed!r} — known: {list(_feeds.FEEDS)}")
    loader = cls()
    docs_fetched = 0
    records: list[dict] = []
    errors = 0
    for url, doc in loader.list_documents(max_docs=max_docs):
        docs_fetched += 1
        try:
            records.extend(_parser.parse_document(doc))
        except Exception as exc:
            errors += 1
            logger.warning(f"[{feed}] parse failed for {url}: {exc}")
    written = _storage.upsert(records)
    logger.info(f"[{feed}] {docs_fetched} docs fetched, {written} records cached, {errors} errors")
    return {"documents_fetched": docs_fetched, "records_written": written, "errors": errors}


def get_for_cves(cve_ids: Iterable[str]) -> dict[str, list[dict]]:
    """Return {cve_id: [advisory_record, ...]} — may be empty for unseen CVEs."""
    return _storage.get_by_cve(list(cve_ids))


def stats() -> dict:
    return _storage.stats()


__all__ = ["init", "refresh", "get_for_cves", "stats"]
