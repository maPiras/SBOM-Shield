"""
SQLite persistence layer.

Schema overview
---------------
scans                 One row per completed scan run.
vulnerable_components One row per vulnerable package found in a scan.
vulnerabilities       One row per individual CVE/GHSA entry linked to a component.
skipped_components    Components that were skipped (no version, unknown ecosystem).
users                 Dashboard user accounts (email + bcrypt hash).

All tables use INTEGER PRIMARY KEY AUTOINCREMENT as surrogate keys.
Foreign keys are enforced via PRAGMA foreign_keys = ON (WAL mode for concurrency).

Read functions return plain dicts/lists so callers do not need to import
sqlite3.Row.  They are designed to serve the dashboard API endpoints directly.
"""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "scans.db"

# ─── Schema ───────────────────────────────────────────────────────────────────

_SCHEMA = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS scans (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    target            TEXT    NOT NULL,
    verdict           TEXT    NOT NULL CHECK(verdict IN ('PASS','WARN','FAIL')),
    total_components  INTEGER NOT NULL DEFAULT 0,
    vulnerable_count  INTEGER NOT NULL DEFAULT 0,
    skipped_count     INTEGER NOT NULL DEFAULT 0,
    total_vulns       INTEGER NOT NULL DEFAULT 0,
    critical_count    INTEGER NOT NULL DEFAULT 0,
    high_count        INTEGER NOT NULL DEFAULT 0,
    medium_count      INTEGER NOT NULL DEFAULT 0,
    low_count         INTEGER NOT NULL DEFAULT 0,
    kev_count         INTEGER NOT NULL DEFAULT 0,
    ot_enabled        INTEGER NOT NULL DEFAULT 1,
    ot_components     INTEGER NOT NULL DEFAULT 0,
    generated_at      TEXT    NOT NULL,
    created_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS vulnerable_components (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name             TEXT    NOT NULL,
    version          TEXT,
    ecosystem        TEXT,
    highest_severity TEXT,
    max_cvss         REAL,
    max_epss         REAL
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    component_id    INTEGER NOT NULL REFERENCES vulnerable_components(id) ON DELETE CASCADE,
    vuln_id         TEXT    NOT NULL,
    source          TEXT,
    severity        TEXT,
    cvss_score      REAL,
    epss_score      REAL,
    epss_percentile REAL,
    summary         TEXT,
    fixed_version   TEXT
);

CREATE TABLE IF NOT EXISTS skipped_components (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name    TEXT    NOT NULL,
    reason  TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Indexes used by the dashboard read queries
CREATE INDEX IF NOT EXISTS idx_scans_generated_at   ON scans(generated_at);
CREATE INDEX IF NOT EXISTS idx_scans_verdict        ON scans(verdict);
CREATE INDEX IF NOT EXISTS idx_vulns_scan_id        ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_source         ON vulnerabilities(source);
CREATE INDEX IF NOT EXISTS idx_vulns_severity       ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_comps_scan_id        ON vulnerable_components(scan_id);
"""

# ─── Connection ───────────────────────────────────────────────────────────────

def get_conn() -> sqlite3.Connection:
    """
    Open (or reuse) a SQLite connection with Row factory enabled.

    check_same_thread=False is required because FastAPI serves requests on
    worker threads while the connection may have been created on another.
    WAL mode allows concurrent reads during a write transaction.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


_MIGRATIONS = [
    "ALTER TABLE scans ADD COLUMN ot_enabled    INTEGER NOT NULL DEFAULT 1",
    "ALTER TABLE scans ADD COLUMN ot_components INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN detected_json TEXT",
    "ALTER TABLE scans ADD COLUMN sbom_json     TEXT",
    # Prioritisation + tracking columns (added 2026-05-12)
    "ALTER TABLE scans ADD COLUMN version               TEXT",
    "ALTER TABLE scans ADD COLUMN track_id              INTEGER",
    "ALTER TABLE scans ADD COLUMN context_profile_json  TEXT",
    "ALTER TABLE scans ADD COLUMN priority_json         TEXT",
    "ALTER TABLE scans ADD COLUMN priority_act_count    INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN priority_attend_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN priority_trackstar_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN priority_track_count  INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE vulnerabilities ADD COLUMN priority_json TEXT",
]

# Tables added after the original schema. Created (IF NOT EXISTS) on every
# init_db() so a stale DB picks them up at first server start.
_EXTRA_TABLES = """
CREATE TABLE IF NOT EXISTS tracks (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    project_name          TEXT    NOT NULL,
    repo_path             TEXT    NOT NULL,
    current_version       TEXT,
    context_profile_json  TEXT    NOT NULL,
    interval_hours        INTEGER NOT NULL DEFAULT 24,
    enabled               INTEGER NOT NULL DEFAULT 1,
    last_check_at         TEXT,
    last_scan_id          INTEGER,
    options_json          TEXT,
    created_at            TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_tracks_enabled       ON tracks(enabled);
CREATE INDEX IF NOT EXISTS idx_tracks_last_check    ON tracks(last_check_at);
CREATE INDEX IF NOT EXISTS idx_scans_track_id       ON scans(track_id);
"""


def init_db() -> None:
    """Create all tables and indexes if they do not already exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(_SCHEMA)
        for stmt in _MIGRATIONS:
            try:
                conn.execute(stmt)
                conn.commit()
            except sqlite3.OperationalError:
                pass  # column already exists
        conn.executescript(_EXTRA_TABLES)


# ─── Write ────────────────────────────────────────────────────────────────────

def save_scan(report: dict) -> int:  # noqa: C901
    """
    Persist a complete security_report dict to SQLite.

    Inserts one row into scans, one per vulnerable component into
    vulnerable_components, one per vulnerability into vulnerabilities, and
    one per skipped component into skipped_components.

    Returns the new scan id.
    """
    summary = report.get("summary", {})
    by_sev  = summary.get("by_severity", {})

    # Count KEV matches by inspecting individual vulnerability source fields
    kev_count = sum(
        1
        for comp in report.get("vulnerable_components", [])
        for v    in comp.get("vulns", [])
        if v.get("source") == "CISA-KEV"
    )

    # extended_coverage metadata
    ec           = report.get("extended_coverage", {})
    ot_enabled  = 1 if ec.get("enabled", False) else 0
    ot_comps    = ec.get("enrichment", {}).get("added", 0)

    import json as _json
    detected_json = _json.dumps(report.get("detected", []))
    sbom_json     = _json.dumps(report.get("sbom_components", []))

    # Prioritisation metadata (optional — present when core.priority has run)
    pri          = report.get("priority") or {}
    pri_buckets  = pri.get("buckets", {})
    priority_json = _json.dumps(pri) if pri else None
    ctx_profile_json = _json.dumps(pri.get("profile")) if pri.get("profile") else None

    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO scans (
                target, verdict,
                total_components, vulnerable_count, skipped_count, total_vulns,
                critical_count, high_count, medium_count, low_count, kev_count,
                ot_enabled, ot_components,
                generated_at, detected_json, sbom_json,
                version, track_id, context_profile_json, priority_json,
                priority_act_count, priority_attend_count,
                priority_trackstar_count, priority_track_count
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                report.get("target", ""),
                report.get("verdict", "PASS"),
                summary.get("total",       0),
                summary.get("vulnerable",  0),
                summary.get("skipped",     0),
                summary.get("total_vulns", 0),
                by_sev.get("CRITICAL", 0),
                by_sev.get("HIGH",     0),
                by_sev.get("MEDIUM",   0),
                by_sev.get("LOW",      0),
                kev_count,
                ot_enabled,
                ot_comps,
                report.get("generated_at", datetime.now(timezone.utc).isoformat()),
                detected_json,
                sbom_json,
                report.get("version"),
                report.get("track_id"),
                ctx_profile_json,
                priority_json,
                pri_buckets.get("Act",     0),
                pri_buckets.get("Attend",  0),
                pri_buckets.get("Track*",  0),
                pri_buckets.get("Track",   0),
            ),
        )
        scan_id = cur.lastrowid

        for comp in report.get("vulnerable_components", []):
            cur2 = conn.execute(
                """
                INSERT INTO vulnerable_components
                    (scan_id, name, version, ecosystem, highest_severity, max_cvss, max_epss)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    scan_id,
                    comp.get("name"),
                    comp.get("version"),
                    comp.get("ecosystem"),
                    comp.get("highest_severity"),
                    comp.get("max_cvss"),
                    comp.get("max_epss"),
                ),
            )
            comp_id = cur2.lastrowid

            for v in comp.get("vulns", []):
                v_pri = v.get("priority")
                conn.execute(
                    """
                    INSERT INTO vulnerabilities (
                        scan_id, component_id, vuln_id, source, severity,
                        cvss_score, epss_score, epss_percentile, summary, fixed_version,
                        priority_json
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        scan_id, comp_id,
                        v.get("id"),
                        v.get("source"),
                        v.get("severity"),
                        v.get("cvss"),
                        v.get("epss"),
                        v.get("epss_percentile"),
                        v.get("summary"),
                        v.get("fixed"),
                        _json.dumps(v_pri) if v_pri else None,
                    ),
                )

        for s in report.get("skipped", []):
            conn.execute(
                "INSERT INTO skipped_components (scan_id, name, reason) VALUES (?,?,?)",
                (scan_id, s.get("name"), s.get("reason")),
            )

        conn.commit()

    return scan_id


# ─── Read — dashboard API queries ─────────────────────────────────────────────

def get_summary() -> dict:
    """
    Aggregate KPI counts across all scans.

    Used by the /api/pipeline/summary dashboard endpoint.
    """
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*)                       AS total_scans,
                COUNT(DISTINCT target)         AS active_projects,
                COALESCE(SUM(total_vulns), 0)  AS open_vulns,
                COALESCE(SUM(kev_count),   0)  AS kev_matches
            FROM scans
            """
        ).fetchone()
    return {
        "totalScans":     row["total_scans"],
        "activeProjects": row["active_projects"],
        "openVulns":      row["open_vulns"],
        "kevMatches":     row["kev_matches"],
    }


def get_recent_scans(limit: int = 6) -> list[dict]:
    """
    Return the most recent *limit* scans, formatted for the dashboard table.

    The project name is derived from the last path component of the target.
    Timestamps are truncated to minute precision (ISO → "YYYY-MM-DD HH:MM").
    """
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, target, verdict, total_components, total_vulns, kev_count,
                   ot_enabled, ot_components, generated_at
            FROM   scans
            ORDER  BY generated_at DESC
            LIMIT  ?
            """,
            (limit,),
        ).fetchall()

    result = []
    for r in rows:
        target  = r["target"] or ""
        project = Path(target).name or target
        ts_raw  = r["generated_at"] or ""
        ts      = ts_raw[:16].replace("T", " ") if ts_raw else "—"
        result.append({
            "id":         r["id"],
            "project":    project,
            "release":    "—",
            "components": r["total_components"],
            "vulns":      r["total_vulns"],
            "kev":        r["kev_count"],
            "verdict":    r["verdict"],
            "ts":         ts,
            "ot_enabled":    bool(r["ot_enabled"]),
            "ot_components": r["ot_components"],
        })
    return result


def get_scan_detail(scan_id: int) -> dict | None:
    """
    Return full detail for a single scan, including vulnerable and skipped
    components.  Used by the /api/scans/<id>/detail endpoint.
    """
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT id, target, verdict, total_components, vulnerable_count,
                   skipped_count, total_vulns, critical_count, high_count,
                   medium_count, low_count, kev_count,
                   ot_enabled, ot_components, generated_at,
                   detected_json, sbom_json
            FROM scans WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()
        if not row:
            return None

        target  = row["target"] or ""
        project = Path(target).name or target

        comps = conn.execute(
            """
            SELECT id, name, version, ecosystem, highest_severity, max_cvss, max_epss
            FROM vulnerable_components WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchall()

        vuln_rows = conn.execute(
            """
            SELECT component_id, vuln_id, source, severity,
                   cvss_score, epss_score, epss_percentile, summary, fixed_version,
                   priority_json
            FROM vulnerabilities WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchall()

        # Group vulns by component_id
        import json as _json_r
        from collections import defaultdict
        vulns_by_comp: dict[int, list] = defaultdict(list)
        for v in vuln_rows:
            pri_raw = v["priority_json"]
            vulns_by_comp[v["component_id"]].append({
                "id":              v["vuln_id"],
                "source":          v["source"],
                "severity":        v["severity"],
                "cvss":            v["cvss_score"],
                "epss":            v["epss_score"],
                "epss_percentile": v["epss_percentile"],
                "summary":         v["summary"],
                "fixed":           v["fixed_version"],
                "priority":        _json_r.loads(pri_raw) if pri_raw else None,
            })

        skipped = conn.execute(
            "SELECT name, reason FROM skipped_components WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()

    import json as _json

    comp_list = [
        {
            "id":               c["id"],
            "name":             c["name"],
            "version":          c["version"],
            "ecosystem":        c["ecosystem"],
            "highest_severity": c["highest_severity"],
            "max_cvss":         c["max_cvss"],
            "max_epss":         c["max_epss"],
            "vulns":            vulns_by_comp.get(c["id"], []),
        }
        for c in comps
    ]
    skipped_list = [{"name": s["name"], "reason": s["reason"]} for s in skipped]

    summary = {
        "total_components": row["total_components"],
        "vulnerable":       row["vulnerable_count"],
        "skipped":          row["skipped_count"],
        "total_vulns":      row["total_vulns"],
        "critical":         row["critical_count"],
        "high":             row["high_count"],
        "medium":           row["medium_count"],
        "low":              row["low_count"],
        "kev":              row["kev_count"],
    }

    return {
        "id":               row["id"],
        "project":          project,
        "target":           target,
        "release":          "—",
        "verdict":          row["verdict"],
        "generated_at":     row["generated_at"],
        "ot_enabled":       bool(row["ot_enabled"]),
        "ot_components":    row["ot_components"],
        "summary":          summary,
        "components":       comp_list,
        "skipped":          skipped_list,
        "detected":         _json.loads(row["detected_json"] or "[]"),
        "sbom_components":  _json.loads(row["sbom_json"]     or "[]"),
    }


def search_scans(q: str = "", limit: int = 50) -> list[dict]:
    """
    Search scans by target name.  If *q* is empty, returns the most recent scans.
    """
    with get_conn() as conn:
        if q:
            rows = conn.execute(
                """
                SELECT id, target, verdict, total_components, total_vulns,
                       kev_count, ot_enabled, ot_components, generated_at
                FROM scans
                WHERE target LIKE ?
                ORDER BY generated_at DESC
                LIMIT ?
                """,
                (f"%{q}%", limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, target, verdict, total_components, total_vulns,
                       kev_count, ot_enabled, ot_components, generated_at
                FROM scans
                ORDER BY generated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

    result = []
    for r in rows:
        target  = r["target"] or ""
        project = Path(target).name or target
        ts_raw  = r["generated_at"] or ""
        ts      = ts_raw[:16].replace("T", " ") if ts_raw else "—"
        result.append({
            "id":            r["id"],
            "project":       project,
            "release":       "—",
            "components":    r["total_components"],
            "vulns":         r["total_vulns"],
            "kev":           r["kev_count"],
            "verdict":       r["verdict"],
            "ts":            ts,
            "ot_enabled":    bool(r["ot_enabled"]),
            "ot_components": r["ot_components"],
        })
    return result


def get_severity_breakdown() -> dict:
    """Aggregate severity counts across all scans for the dashboard bar chart."""
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT
                COALESCE(SUM(critical_count), 0) AS critical,
                COALESCE(SUM(high_count),     0) AS high,
                COALESCE(SUM(medium_count),   0) AS medium,
                COALESCE(SUM(low_count),      0) AS low
            FROM scans
            """
        ).fetchone()
    return {k: row[k] for k in ("critical", "high", "medium", "low")}


def get_sources_stats() -> list[dict]:
    """
    Count vulnerabilities grouped by source (OSV / NVD / CISA-KEV).

    Used by the dashboard "Vuln sources" panel.
    """
    _meta = {
        "OSV":      ("OSV API",  "osv.dev"),
        "NVD":      ("NVD",      "nvd.nist.gov"),
        "CISA-KEV": ("CISA KEV", "cisa.gov"),
    }
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT source, COUNT(*) AS cnt FROM vulnerabilities GROUP BY source"
        ).fetchall()

    result = []
    for r in rows:
        src       = r["source"] or "OSV"
        name, lbl = _meta.get(src, (src, src))
        result.append({"name": name, "count": r["cnt"], "label": lbl})
    return result


def get_trend(days: int = 7) -> dict:
    """
    Return daily scan counts split by verdict for the last *days* days.

    Days with no scans are filled with zeros so the chart always shows a
    complete time axis.
    """
    from datetime import date, timedelta

    today  = date.today()
    dates  = [(today - timedelta(days=days - 1 - i)).isoformat() for i in range(days)]
    labels = [(today - timedelta(days=days - 1 - i)).strftime("%b %d") for i in range(days)]

    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT date(generated_at) AS day, verdict, COUNT(*) AS cnt
            FROM   scans
            WHERE  date(generated_at) >= ?
            GROUP  BY day, verdict
            """,
            (dates[0],),
        ).fetchall()

    counts = {d: {"FAIL": 0, "WARN": 0, "PASS": 0} for d in dates}
    for r in rows:
        d, v = r["day"], r["verdict"]
        if d in counts and v in counts[d]:
            counts[d][v] = r["cnt"]

    return {
        "labels": labels,
        "fail":   [counts[d]["FAIL"] for d in dates],
        "warn":   [counts[d]["WARN"] for d in dates],
        "pass":   [counts[d]["PASS"] for d in dates],
    }


# ─── Tracking ─────────────────────────────────────────────────────────────────

def create_track(
    project_name: str,
    repo_path: str,
    current_version: str,
    context_profile: dict,
    interval_hours: int = 24,
    options: dict | None = None,
) -> int:
    """Insert a new track row and return its id."""
    import json as _json
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO tracks (
                project_name, repo_path, current_version,
                context_profile_json, interval_hours, options_json
            ) VALUES (?,?,?,?,?,?)
            """,
            (
                project_name,
                repo_path,
                current_version,
                _json.dumps(context_profile),
                int(interval_hours),
                _json.dumps(options or {}),
            ),
        )
        conn.commit()
        return cur.lastrowid


def update_track_after_scan(track_id: int, scan_id: int) -> None:
    """Set last_check_at + last_scan_id after a successful tracked scan."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE tracks SET last_check_at = ?, last_scan_id = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), scan_id, track_id),
        )
        conn.commit()


def upgrade_track_version(track_id: int, new_version: str) -> None:
    """Replace the tracked version. Old scans remain in `scans` (linked by
    track_id) so the history is preserved."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE tracks SET current_version = ? WHERE id = ?",
            (new_version, track_id),
        )
        conn.commit()


def disable_track(track_id: int) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE tracks SET enabled = 0 WHERE id = ?", (track_id,))
        conn.commit()


def delete_track(track_id: int) -> None:
    """Soft-detach: drop the track row but keep linked scans (set track_id NULL)."""
    with get_conn() as conn:
        conn.execute("UPDATE scans SET track_id = NULL WHERE track_id = ?", (track_id,))
        conn.execute("DELETE FROM tracks WHERE id = ?", (track_id,))
        conn.commit()


def get_track(track_id: int) -> dict | None:
    import json as _json
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM tracks WHERE id = ?", (track_id,)
        ).fetchone()
    if not row:
        return None
    return _track_row_to_dict(row, _json)


def list_tracks(only_enabled: bool = False) -> list[dict]:
    import json as _json
    sql = "SELECT * FROM tracks"
    if only_enabled:
        sql += " WHERE enabled = 1"
    sql += " ORDER BY created_at DESC"
    with get_conn() as conn:
        rows = conn.execute(sql).fetchall()
    return [_track_row_to_dict(r, _json) for r in rows]


def get_track_history(track_id: int) -> list[dict]:
    """All scans associated with this track, oldest first — drives the
    'version timeline' panel in the GUI."""
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, version, verdict, total_components, total_vulns,
                   priority_act_count, priority_attend_count,
                   priority_trackstar_count, priority_track_count,
                   kev_count, generated_at
            FROM scans WHERE track_id = ? ORDER BY generated_at ASC
            """,
            (track_id,),
        ).fetchall()
    return [
        {
            "scan_id":  r["id"],
            "version":  r["version"] or "—",
            "verdict":  r["verdict"],
            "components":  r["total_components"],
            "vulns":       r["total_vulns"],
            "act":         r["priority_act_count"],
            "attend":      r["priority_attend_count"],
            "trackstar":   r["priority_trackstar_count"],
            "track":       r["priority_track_count"],
            "kev":         r["kev_count"],
            "ts":          (r["generated_at"] or "")[:16].replace("T", " "),
        }
        for r in rows
    ]


def _track_row_to_dict(row, _json) -> dict:
    return {
        "id":              row["id"],
        "project_name":    row["project_name"],
        "repo_path":       row["repo_path"],
        "current_version": row["current_version"],
        "context_profile": _json.loads(row["context_profile_json"] or "{}"),
        "interval_hours":  row["interval_hours"],
        "enabled":         bool(row["enabled"]),
        "last_check_at":   row["last_check_at"],
        "last_scan_id":    row["last_scan_id"],
        "options":         _json.loads(row["options_json"] or "{}"),
        "created_at":      row["created_at"],
    }


def get_due_tracks(now_utc: datetime) -> list[dict]:
    """Tracks whose last_check_at + interval_hours <= now (or never checked)."""
    import json as _json
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM tracks WHERE enabled = 1"
        ).fetchall()
    due = []
    for r in rows:
        last = r["last_check_at"]
        if not last:
            due.append(_track_row_to_dict(r, _json))
            continue
        try:
            last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
        except ValueError:
            due.append(_track_row_to_dict(r, _json))
            continue
        delta_h = (now_utc - last_dt).total_seconds() / 3600.0
        if delta_h >= r["interval_hours"]:
            due.append(_track_row_to_dict(r, _json))
    return due


# ─── Misc reads ───────────────────────────────────────────────────────────────

def get_kev_active(limit: int = 20) -> list[dict]:
    """
    Return the highest-scoring CISA KEV entries across all scans.

    Used by the "Active KEV matches" dashboard panel.
    Score >= 9.0 is labelled "crit", lower is "high".
    """
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT vuln_id, summary, cvss_score
            FROM   vulnerabilities
            WHERE  source = 'CISA-KEV'
            ORDER  BY cvss_score DESC
            LIMIT  ?
            """,
            (limit,),
        ).fetchall()

    result = []
    for r in rows:
        score = r["cvss_score"] or 0.0
        result.append({
            "cve":   r["vuln_id"],
            "desc":  r["summary"] or "No description",
            "score": score,
            "sev":   "crit" if score >= 9.0 else "high",
        })
    return result
