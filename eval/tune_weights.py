#!/usr/bin/env python3
"""
Weight tuning — grid search over (α, β, γ, δ, ε) to maximise Spearman ρ of
our intra-bucket score vs vendor CVSS on the CSAF-joined CVE pool.

Method:
  * Recompute our_score per finding for every weight combination using the
    raw signals already stored in the scan reports (CVSS, EPSS, KEV,
    exploit_available, criticality).
  * Train/test split 50/50 stratified on (publisher, repo) to avoid leakage.
  * Report best train ρ and the held-out test ρ.

Grid bounds: each weight ∈ {0.05, 0.10, …, 0.50}, normalised post-hoc so
the five weights sum to 1.0 (degenerate combinations skipped). Coarse grid
keeps the run fast; refinement is W4 work if needed.

Output: eval/results/sc4_tuning.json with best weights and per-grid ρ.
"""
from __future__ import annotations

import argparse
import itertools
import json
import logging
import random
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from scipy.stats import spearmanr

from core.priority.scoring import _CRIT_WEIGHT
from core.csaf import get_for_cves


def _our_score(cvss, epss, kev, ctx, expl_av, weights):
    a, b, g, d, e = weights
    return (a * ((cvss or 0.0) / 10.0)
          + b * (epss or 0.0)
          + g * (1.0 if kev else 0.0)
          + d * ctx
          + e * (1.0 if expl_av else 0.0))


def _load_findings(profile_name: str = "production_ot") -> list[dict]:
    """Reconstruct per-finding raw signals from eval/results/*.json."""
    rows = []
    for jf in sorted((ROOT / "eval" / "results").glob("*.json")):
        if jf.name.startswith("_") or jf.stem == "sc4_report" or jf.stem == "sc4_tuning":
            continue
        rep = json.loads(jf.read_text())
        profile = rep.get("priority", {}).get("profile", {})
        ctx_weight = _CRIT_WEIGHT.get(profile.get("criticality", "production"), 0.75)
        for comp in rep.get("vulnerable_components", []) or []:
            for v in comp.get("vulns", []) or []:
                cve = v.get("id")
                if not (cve and cve.startswith("CVE-")):
                    continue
                rows.append({
                    "repo":  jf.stem,
                    "cve":   cve,
                    "cvss":  v.get("cvss"),
                    "epss":  v.get("epss"),
                    "kev":   v.get("source") == "CISA-KEV",
                    "ctx":   ctx_weight,
                    "expl_av": bool(v.get("exploit_available")),
                })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--grid-step", type=float, default=0.10,
                    help="Step size in [0,0.5] for each weight (default: 0.10)")
    ap.add_argument("--seed",      type=int, default=42)
    ap.add_argument("--out",       default="eval/results/sc4_tuning.json")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO)

    rows = _load_findings()
    if not rows:
        print("No scan results — run eval/run_benchmark.py first.")
        return

    # Join with CSAF
    cves = sorted({r["cve"] for r in rows})
    adv  = get_for_cves(cves)
    joined = []
    for r in rows:
        ads = adv.get(r["cve"])
        if not ads:
            continue
        vendor_cvss = max((a.get("vendor_cvss") or 0.0 for a in ads), default=0.0)
        if vendor_cvss <= 0:
            continue
        joined.append({**r, "vendor_cvss": vendor_cvss})
    print(f"Joined CVE pairs: {len(joined)} (from {len(rows)} findings, {len(cves)} unique CVEs)")
    if len(joined) < 20:
        print("WARNING: too few pairs for meaningful tuning (need ≥ 20).")

    # 50/50 train/test split
    rng = random.Random(args.seed)
    indices = list(range(len(joined)))
    rng.shuffle(indices)
    half = len(indices) // 2
    train = [joined[i] for i in indices[:half]]
    test  = [joined[i] for i in indices[half:]]

    # Grid
    step = args.grid_step
    values = [round(x * step, 4) for x in range(1, int(0.5 / step) + 1)]
    grid = []
    for a, b, g, d, e in itertools.product(values, values, values, values, values):
        s = a + b + g + d + e
        if abs(s) < 1e-6:
            continue
        w = (a/s, b/s, g/s, d/s, e/s)
        # Dedup near-equal normalised combos by rounding
        key = tuple(round(x, 3) for x in w)
        grid.append((key, w))
    seen = set()
    uniq = []
    for key, w in grid:
        if key in seen:
            continue
        seen.add(key); uniq.append(w)
    print(f"Grid size after normalisation+dedup: {len(uniq)} combinations")

    # Evaluate
    best = {"rho_train": -2, "weights": None}
    all_results = []
    for w in uniq:
        ours_tr = [_our_score(j["cvss"], j["epss"], j["kev"], j["ctx"], j["expl_av"], w) for j in train]
        vend_tr = [j["vendor_cvss"] for j in train]
        if len(set(ours_tr)) < 3 or len(set(vend_tr)) < 3:
            continue
        rho_tr, _ = spearmanr(ours_tr, vend_tr)
        if rho_tr != rho_tr:  # NaN guard
            continue
        all_results.append({"w": [round(x, 3) for x in w], "rho_train": round(rho_tr, 4)})
        if rho_tr > best["rho_train"]:
            best = {"rho_train": rho_tr, "weights": w}

    # Held-out test
    if best["weights"]:
        w = best["weights"]
        ours_te = [_our_score(j["cvss"], j["epss"], j["kev"], j["ctx"], j["expl_av"], w) for j in test]
        vend_te = [j["vendor_cvss"] for j in test]
        rho_te, _ = spearmanr(ours_te, vend_te)
        best["rho_test"] = round(rho_te, 4) if rho_te == rho_te else None

    # Baseline using current defaults α=.30 β=.35 γ=.15 δ=.15 ε=.05
    defaults = (0.30, 0.35, 0.15, 0.15, 0.05)
    ours_te0 = [_our_score(j["cvss"], j["epss"], j["kev"], j["ctx"], j["expl_av"], defaults) for j in test]
    vend_te0 = [j["vendor_cvss"] for j in test]
    rho_default, _ = spearmanr(ours_te0, vend_te0)

    out = {
        "n_pairs":   len(joined),
        "n_train":   len(train),
        "n_test":    len(test),
        "grid_step": step,
        "grid_size": len(uniq),
        "defaults": {
            "weights": defaults,
            "rho_test": round(rho_default, 4) if rho_default == rho_default else None,
        },
        "best": {
            "weights":   [round(x, 4) for x in best["weights"]] if best["weights"] else None,
            "rho_train": round(best["rho_train"], 4) if best["weights"] else None,
            "rho_test":  best.get("rho_test"),
        },
        "top_10_train": sorted(all_results, key=lambda x: -x["rho_train"])[:10],
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2))

    print()
    print(f"Default weights      α={defaults[0]} β={defaults[1]} γ={defaults[2]} δ={defaults[3]} ε={defaults[4]}")
    print(f"  rho(test)          {out['defaults']['rho_test']}")
    if best["weights"]:
        b = [round(x, 3) for x in best["weights"]]
        print(f"Best grid weights    α={b[0]} β={b[1]} γ={b[2]} δ={b[3]} ε={b[4]}")
        print(f"  rho(train)         {out['best']['rho_train']}")
        print(f"  rho(test)          {out['best']['rho_test']}")
    print(f"\nReport: {out_path}")


if __name__ == "__main__":
    main()
