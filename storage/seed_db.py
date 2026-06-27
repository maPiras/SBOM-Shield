#!/usr/bin/env python3
"""
Seed the database:
  1. Create default admin + user accounts.
  2. Import any existing JSON reports from ./reports/.

Usage:
    python seed_db.py
    python seed_db.py --reports-dir /path/to/reports
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import bcrypt

from storage.database import get_conn, init_db, save_scan


# ─── Default credentials (change before production) ──────────────────────────

DEFAULT_USERS = [
    {"email": "admin@sbom-shield.local", "password": "admin1234",  "is_admin": True},
    {"email": "user@sbom-shield.local",  "password": "user1234",   "is_admin": False},
]


def seed_users() -> None:
    with get_conn() as conn:
        for u in DEFAULT_USERS:
            existing = conn.execute(
                "SELECT id FROM users WHERE email = ?", (u["email"],)
            ).fetchone()
            if existing:
                print(f"  [skip] {u['email']} — already exists")
                continue
            pw_hash = bcrypt.hashpw(u["password"].encode(), bcrypt.gensalt()).decode()
            conn.execute(
                "INSERT INTO users (email, password_hash, is_admin) VALUES (?,?,?)",
                (u["email"], pw_hash, int(u["is_admin"])),
            )
            conn.commit()
            role = "admin" if u["is_admin"] else "user"
            print(f"  [+] {u['email']}  ({role})  pw={u['password']}")


def import_reports(reports_dir: Path) -> None:
    report_files = sorted(reports_dir.glob("security_report*.json"))
    if not report_files:
        # also try plain security_report.json
        plain = reports_dir / "security_report.json"
        if plain.exists():
            report_files = [plain]

    if not report_files:
        print("  [skip] no report files found")
        return

    for path in report_files:
        try:
            report = json.loads(path.read_text())
        except Exception as e:
            print(f"  [err]  {path.name}: {e}")
            continue

        # Check for duplicate (same target + generated_at)
        with get_conn() as conn:
            dup = conn.execute(
                "SELECT id FROM scans WHERE target = ? AND generated_at = ?",
                (report.get("target", ""), report.get("generated_at", "")),
            ).fetchone()
        if dup:
            print(f"  [skip] {path.name} — already in DB (scan id={dup['id']})")
            continue

        scan_id = save_scan(report)
        target  = report.get("target", "?")
        verdict = report.get("verdict", "?")
        vulns   = report.get("summary", {}).get("total_vulns", 0)
        print(f"  [+]    {path.name}  →  scan_id={scan_id}  target={target}  verdict={verdict}  vulns={vulns}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed the SBOM-Shield database")
    parser.add_argument(
        "--reports-dir",
        default=str(ROOT / "reports"),
        help="Directory containing security_report*.json files",
    )
    args = parser.parse_args()

    print("Initialising database...")
    init_db()

    print("\nSeeding users:")
    seed_users()

    print(f"\nImporting reports from {args.reports_dir}:")
    import_reports(Path(args.reports_dir))

    print("\nDone.")


if __name__ == "__main__":
    main()
