"""
SQLite cache for parsed CSAF advisories.

One row per (advisory_id, cve_id) — a single advisory can mention multiple
CVEs and we want each to be queryable individually.

The cache is additive: re-running a fetch upserts on the unique
(advisory_id, cve_id) key, so re-fetching is idempotent.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from storage.database import get_conn

_SCHEMA = """
CREATE TABLE IF NOT EXISTS csaf_advisories (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id     TEXT    NOT NULL,
    publisher       TEXT    NOT NULL,
    release_date    TEXT,
    title           TEXT,
    tlp_label       TEXT,
    cve_id          TEXT    NOT NULL,
    vendor_cvss     REAL,
    vendor_severity TEXT,
    affected_products_json TEXT,
    fetched_at      TEXT    NOT NULL,
    UNIQUE(advisory_id, cve_id) ON CONFLICT REPLACE
);

CREATE INDEX IF NOT EXISTS idx_csaf_cve       ON csaf_advisories(cve_id);
CREATE INDEX IF NOT EXISTS idx_csaf_publisher ON csaf_advisories(publisher);
"""


def init_schema() -> None:
    with get_conn() as conn:
        conn.executescript(_SCHEMA)
        conn.commit()


def upsert(records: list[dict]) -> int:
    """Insert / replace a batch of parsed records. Returns row count written."""
    if not records:
        return 0
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.executemany(
            """
            INSERT OR REPLACE INTO csaf_advisories
              (advisory_id, publisher, release_date, title, tlp_label,
               cve_id, vendor_cvss, vendor_severity,
               affected_products_json, fetched_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            [
                (
                    r["advisory_id"], r["publisher"], r.get("release_date"),
                    r.get("title"), r.get("tlp_label"),
                    r["cve_id"], r.get("vendor_cvss"), r.get("vendor_severity"),
                    json.dumps(r.get("affected_products") or []),
                    now,
                )
                for r in records
            ],
        )
        conn.commit()
    return len(records)


def get_by_cve(cve_ids: list[str]) -> dict[str, list[dict]]:
    """Return {cve_id: [advisory dict, ...]} for the requested CVE list."""
    if not cve_ids:
        return {}
    placeholders = ",".join("?" * len(cve_ids))
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT advisory_id, publisher, release_date, title, cve_id,
                   vendor_cvss, vendor_severity, affected_products_json
            FROM csaf_advisories
            WHERE cve_id IN ({placeholders})
            """,
            cve_ids,
        ).fetchall()
    out: dict[str, list[dict]] = {}
    for r in rows:
        out.setdefault(r["cve_id"], []).append({
            "advisory_id":     r["advisory_id"],
            "publisher":       r["publisher"],
            "release_date":    r["release_date"],
            "title":           r["title"],
            "vendor_cvss":     r["vendor_cvss"],
            "vendor_severity": r["vendor_severity"],
            "affected_products": json.loads(r["affected_products_json"] or "[]"),
        })
    return out


def stats() -> dict:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT publisher, COUNT(DISTINCT advisory_id) AS adv,
                                COUNT(DISTINCT cve_id) AS cves,
                                COUNT(*) AS rows
            FROM csaf_advisories GROUP BY publisher
            """
        ).fetchall()
    return {r["publisher"]: {
        "advisories": r["adv"], "cves": r["cves"], "rows": r["rows"]
    } for r in rows}
