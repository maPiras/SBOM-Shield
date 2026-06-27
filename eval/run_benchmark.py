#!/usr/bin/env python3
"""
Benchmark batch runner — scan every repo under REPOS_DIR with priority on.

Each scan is recorded in `scans` with a 'benchmark' tag so the analyser
script can find them later. We use the production_ot context profile by
default because it is the most permissive (more vulns land in Act/Attend
buckets) — this maximises the CVE pool for the Spearman/κ join with CSAF.

Usage:
    python3 eval/run_benchmark.py [--profile production_ot] [--only repo1,repo2]
"""
import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core.pipeline import run_pipeline
from storage.database import init_db, save_scan

REPOS_DIR = Path(os.environ.get("SBOMSHIELD_REPOS_DIR", str(Path.home() / "repos")))
RESULTS_DIR = ROOT / "eval" / "results"


def _human_progress(stage: str, pct: int, done: bool = False, error: bool = False):
    # Single-line progress that overwrites itself, leaves error/done permanent
    end = "\n" if (done or error) else "\r"
    print(f"    [{pct:3d}%] {stage:60.60}", end=end, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile",   default="production_ot")
    ap.add_argument("--only",      default=None,
                    help="comma-separated repo names to scan (default: all in REPOS_DIR)")
    ap.add_argument("--skip",      default="",
                    help="comma-separated repo names to skip")
    ap.add_argument("--quiet",     action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        level=logging.WARNING if args.quiet else logging.INFO,
    )

    init_db()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    if args.only:
        repos = [REPOS_DIR / n for n in args.only.split(",") if n.strip()]
    else:
        repos = sorted(p for p in REPOS_DIR.iterdir() if p.is_dir() and not p.name.startswith("."))

    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    repos = [r for r in repos if r.name not in skip]

    print(f"Benchmark: {len(repos)} repos · profile={args.profile}")
    print(f"  → {[r.name for r in repos]}")
    print()

    summary = []
    t_start = time.time()
    for i, repo in enumerate(repos, 1):
        if not repo.exists():
            print(f"[{i}/{len(repos)}] SKIP {repo.name} — path not found"); continue
        print(f"[{i}/{len(repos)}] {repo.name}")
        t0 = time.time()
        try:
            report = run_pipeline(
                repo_path=str(repo),
                version="benchmark",
                context_profile=args.profile,
                track_id=None,
                options={
                    "extended_coverage": True,
                    "include_indirect":  False,
                    "syft_fallback":     False,   # cdxgen only, faster
                    "online_resolution": False,
                },
                emit=None if args.quiet else _human_progress,
            )
        except Exception as exc:
            print(f"    FAILED: {exc}")
            summary.append({"repo": repo.name, "status": "failed", "error": str(exc)})
            continue

        # Tag the scan so the analyser can find it
        report["benchmark"] = True
        scan_id = save_scan(report)
        (RESULTS_DIR / f"{repo.name}.json").write_text(json.dumps(report, indent=2))

        buckets = report.get("priority", {}).get("buckets", {})
        elapsed = time.time() - t0
        print(f"    scan_id={scan_id}  verdict={report['verdict']}  "
              f"Act={buckets.get('Act', 0)} Attend={buckets.get('Attend', 0)} "
              f"Track*={buckets.get('Track*', 0)} Track={buckets.get('Track', 0)}  "
              f"({elapsed:.0f}s)")
        summary.append({
            "repo":    repo.name,
            "scan_id": scan_id,
            "verdict": report["verdict"],
            "buckets": buckets,
            "vulns":   report.get("summary", {}).get("total_vulns", 0),
            "elapsed_s": round(elapsed, 1),
        })

    total = time.time() - t_start
    (RESULTS_DIR / "_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\nTotal: {total/60:.1f} min · {len(summary)} scans → {RESULTS_DIR}/_summary.json")


if __name__ == "__main__":
    main()
