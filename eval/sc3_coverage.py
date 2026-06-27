#!/usr/bin/env python3
"""
SC3 — Detection-coverage delta vs the merged cdxgen+Syft baseline.

This is the experiment the validation chapter (threat-to-validity #2) identified
as future work: the W3 benchmark ran with ``--no-syft-fallback`` and therefore
measured the extended-coverage layer on top of *cdxgen alone*. SC3 re-runs the
SBOM-generation and detection stages with **Syft enabled** so the contribution
is reported as a delta against the full generalist baseline (cdxgen+Syft merged).

It deliberately stops *before* the vulnerability scan: the coverage gap is a
component-source question (cdxgen / syft / manifest / conan / extended_coverage),
so the NVD-rate-limited vuln phase is skipped and the run is fast.

Per repository it reports:
  baseline_cdxgen        components cdxgen found
  baseline_syft          components Syft added beyond cdxgen
  baseline_total         cdxgen + syft   (the generalist merged baseline)
  ext_manifest           manifest-parser additions  (requirements/pyproject/...)
  ext_conan              Conan custom-manifest parser additions
  ext_extended_coverage  OT/ICS static-analysis injections
  ext_total              everything the extended layer adds beyond the baseline
  ext_direct             of ext_total, how many survive reachability (directly_used)
  delta_pct              ext_total / baseline_total * 100

Usage:
    SBOMSHIELD_REPOS_DIR=~/repos python3 eval/sc3_coverage.py [--only a,b] [--skip c]
Output: eval/results/sc3_report.json
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

REPOS_DIR = Path(os.environ.get("SBOMSHIELD_REPOS_DIR", str(Path.home() / "repos")))
RESULTS_DIR = ROOT / "eval" / "results"

_BASELINE_SOURCES = {"cdxgen", "syft"}
_EXT_SOURCES = {"manifest", "conan", "extended_coverage"}


def _assemble(repo_path: str) -> dict:
    """Run SBOM-gen (Syft on) + manifest/conan/extended_coverage + reachability.

    Mirrors pipeline.run_pipeline() steps 1-4b but stops before the vuln scan.
    Returns per-source component tallies.
    """
    from core.sbom_generator import generate_sbom
    from core.sbom_parser import parse_sbom
    from core.requirements_parser import enrich_components as manifest_enrich
    from core.extended_coverage.conan_parser import enrich_components as conan_enrich
    from core.extended_coverage import run as ec_run, enrich as ec_enrich
    from core import noise_filter as reach

    gen = generate_sbom(repo_path, syft_fallback=True, online=False)
    components = parse_sbom(gen.sbom)
    components, _ = manifest_enrich(components, Path(repo_path))
    components, _ = conan_enrich(components, Path(repo_path))

    ec_result = ec_run(repo_path)
    enrich_res = ec_enrich(components, ec_result)
    all_components = list(enrich_res.components)

    reach.tag(all_components, repo_path)

    by_source: dict[str, int] = {}
    ext_direct = 0
    ext_total = 0
    for c in all_components:
        src = getattr(c, "source", None) or "unknown"
        by_source[src] = by_source.get(src, 0) + 1
        if src in _EXT_SOURCES:
            ext_total += 1
            if getattr(c, "directly_used", True):
                ext_direct += 1

    baseline = sum(by_source.get(s, 0) for s in _BASELINE_SOURCES)
    cdxgen = by_source.get("cdxgen", 0)
    syft = by_source.get("syft", 0)
    merge = {}
    if gen.merge_stats:
        merge = {
            "cdxgen_components": gen.merge_stats.primary_count,
            "syft_components": gen.merge_stats.secondary_count,
            "added_from_syft": gen.merge_stats.added_from_secondary,
            "duplicates_skipped": gen.merge_stats.duplicates_skipped,
        }

    return {
        "syft_used": gen.syft_used,
        "by_source": by_source,
        "baseline_cdxgen": cdxgen,
        "baseline_syft": syft,
        "baseline_total": baseline,
        "ext_manifest": by_source.get("manifest", 0),
        "ext_conan": by_source.get("conan", 0),
        "ext_extended_coverage": by_source.get("extended_coverage", 0),
        "ext_total": ext_total,
        "ext_direct": ext_direct,
        "delta_pct": round(100.0 * ext_total / baseline, 1) if baseline else None,
        "merge": merge,
        "ot_found": len(ec_result.components),
        "ot_injected": len(enrich_res.added),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None, help="comma-separated repo names")
    ap.add_argument("--skip", default="", help="comma-separated repo names")
    ap.add_argument("--out", default=str(RESULTS_DIR / "sc3_report.json"))
    args = ap.parse_args()

    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S", level=logging.WARNING,
    )
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    if args.only:
        repos = [REPOS_DIR / n for n in args.only.split(",") if n.strip()]
    else:
        repos = sorted(p for p in REPOS_DIR.iterdir()
                       if p.is_dir() and not p.name.startswith("."))
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    repos = [r for r in repos if r.name not in skip]

    print(f"SC3 coverage (Syft ENABLED): {len(repos)} repos")
    per_repo = []
    agg = {k: 0 for k in ("baseline_cdxgen", "baseline_syft", "baseline_total",
                          "ext_manifest", "ext_conan", "ext_extended_coverage",
                          "ext_total", "ext_direct")}
    t_start = time.time()
    for i, repo in enumerate(repos, 1):
        if not repo.exists():
            print(f"[{i}/{len(repos)}] SKIP {repo.name} — not found"); continue
        t0 = time.time()
        print(f"[{i}/{len(repos)}] {repo.name} ...", flush=True)
        try:
            row = _assemble(str(repo))
        except Exception as exc:  # keep going; record the failure
            import traceback; traceback.print_exc()
            per_repo.append({"repo": repo.name, "error": str(exc)})
            continue
        row["repo"] = repo.name
        row["elapsed_s"] = round(time.time() - t0, 1)
        per_repo.append(row)
        for k in agg:
            agg[k] += row.get(k, 0) or 0
        print(f"    baseline(cdxgen={row['baseline_cdxgen']}+syft={row['baseline_syft']}"
              f"={row['baseline_total']})  ext+{row['ext_total']} "
              f"(direct {row['ext_direct']})  Δ={row['delta_pct']}%  ({row['elapsed_s']}s)")

    agg["delta_pct"] = (round(100.0 * agg["ext_total"] / agg["baseline_total"], 1)
                        if agg["baseline_total"] else None)
    out = {"generated_by": "sc3_coverage.py", "syft_enabled": True,
           "aggregate": agg, "per_repo": per_repo}
    Path(args.out).write_text(json.dumps(out, indent=2))
    print(f"\nTotal {(time.time()-t_start)/60:.1f} min → {args.out}")
    print(f"AGGREGATE: baseline={agg['baseline_total']} "
          f"(cdxgen {agg['baseline_cdxgen']} + syft {agg['baseline_syft']}), "
          f"extended +{agg['ext_total']} (direct {agg['ext_direct']}), "
          f"Δ={agg['delta_pct']}%")


if __name__ == "__main__":
    main()
