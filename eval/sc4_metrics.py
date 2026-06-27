#!/usr/bin/env python3
"""
SC4 — empirical validation of the priority engine vs vendor CSAF.

Joins:
  scan CVEs (from benchmark scans)  ∩  CSAF advisories cache  →  per-CVE pair:
      our_score, our_bucket, vendor_cvss, vendor_severity

Metrics:
  Spearman ρ   continuous: our_score (intra-bucket) vs vendor_cvss
  Cohen κ      categorical: our_bucket vs vendor_bucket  (Mapping B —
               see notes/csaf_validation.txt: Critical→Act, High→Act,
               Medium→Attend, Low→Track*)
  Per-publisher breakdown (Siemens-only, CISA-only, intersection).
  Per-component table (top contributors).

Usage:
    python3 eval/sc4_metrics.py [--out eval/results/sc4_report.json]
"""
import argparse
import json
import logging
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from scipy.stats import spearmanr

from core.csaf import get_for_cves, stats as csaf_stats
from storage.database import get_conn


# Mapping B: lenient — vendor "High" maps to our "Act" (both = action required).
VENDOR_SEV_TO_BUCKET = {
    "CRITICAL": "Act",
    "HIGH":     "Act",
    "MEDIUM":   "Attend",
    "LOW":      "Track*",
    "NONE":     "Track",
}
# When vendor_severity is missing, derive from CVSS.
def _cvss_to_vendor_severity(score):
    if score is None:
        return None
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >  0.0: return "LOW"
    return "NONE"


def _bucket_to_rank(b):
    return {"Act": 3, "Attend": 2, "Track*": 1, "Track": 0}.get(b, -1)


def _cohen_kappa(a, b):
    """Pure-Python Cohen's κ for parallel lists of categorical labels."""
    assert len(a) == len(b)
    if not a:
        return None
    labels = sorted(set(a) | set(b))
    idx = {l: i for i, l in enumerate(labels)}
    n = len(a)
    # confusion matrix
    cm = [[0] * len(labels) for _ in labels]
    for x, y in zip(a, b):
        cm[idx[x]][idx[y]] += 1
    p_o = sum(cm[i][i] for i in range(len(labels))) / n
    row = [sum(cm[i]) for i in range(len(labels))]
    col = [sum(cm[r][i] for r in range(len(labels))) for i in range(len(labels))]
    p_e = sum(row[i] * col[i] for i in range(len(labels))) / (n * n)
    if abs(1 - p_e) < 1e-12:
        return 1.0 if p_o == 1.0 else 0.0
    return (p_o - p_e) / (1 - p_e)


def _collect_scan_vulns(scan_ids: list[int] | None = None) -> list[dict]:
    """All benchmark-scan vulns with our priority breakdown attached.

    Reads from the JSON reports under eval/results/ (richer than DB) but
    falls back to DB if a JSON file is missing."""
    rows = []
    results_dir = ROOT / "eval" / "results"
    json_files = sorted(p for p in results_dir.glob("*.json") if not p.name.startswith("_"))
    for jf in json_files:
        try:
            rep = json.loads(jf.read_text())
        except Exception:
            continue
        repo = jf.stem
        for comp in rep.get("vulnerable_components", []) or []:
            for v in comp.get("vulns", []) or []:
                cve = v.get("id")
                if not cve or not cve.startswith("CVE-"):
                    # Skip GHSA/PYSEC/OSV-only IDs; CSAF feed uses CVE only.
                    # Use the alias if present.
                    cve = (v.get("cve_alias") or v.get("aliases") or [None])[0]
                    if not cve or not str(cve).startswith("CVE-"):
                        continue
                pri = v.get("priority") or {}
                rows.append({
                    "repo":       repo,
                    "component":  comp.get("name"),
                    "cve":        cve,
                    "our_cvss":   v.get("cvss"),
                    "our_epss":   v.get("epss"),
                    "our_bucket": pri.get("bucket"),
                    "our_score":  pri.get("score"),
                    "kev":        v.get("source") == "CISA-KEV",
                })
    return rows


def join_with_csaf(rows: list[dict]) -> list[dict]:
    """Attach vendor CVSS + severity (highest across all advisories per CVE)."""
    cves = sorted({r["cve"] for r in rows})
    adv = get_for_cves(cves)
    out = []
    for r in rows:
        ads = adv.get(r["cve"], [])
        if not ads:
            continue
        # Highest vendor CVSS across all advisories citing this CVE (proxy
        # for "most-severe-vendor-judgement" — we'll also do a per-publisher
        # cut later).
        best = max(ads, key=lambda a: a.get("vendor_cvss") or 0)
        vendor_cvss = best.get("vendor_cvss")
        vendor_sev  = best.get("vendor_severity") or _cvss_to_vendor_severity(vendor_cvss)
        vendor_bucket = VENDOR_SEV_TO_BUCKET.get((vendor_sev or "").upper())
        out.append({**r,
                    "vendor_cvss":   vendor_cvss,
                    "vendor_sev":    vendor_sev,
                    "vendor_bucket": vendor_bucket,
                    "publishers":    sorted({a["publisher"] for a in ads}),
                    "advisory_ids":  [a["advisory_id"] for a in ads],
                    })
    return out


def compute_metrics(joined: list[dict], label: str = "ALL") -> dict:
    if not joined:
        return {"label": label, "n": 0}
    cvss_pairs   = [(j["our_score"], j["vendor_cvss"])
                    for j in joined
                    if j.get("our_score") is not None and j.get("vendor_cvss") is not None]
    cvss_pairs2  = [(j["our_cvss"], j["vendor_cvss"])
                    for j in joined
                    if j.get("our_cvss") is not None and j.get("vendor_cvss") is not None]
    bucket_pairs = [(j["our_bucket"], j["vendor_bucket"])
                    for j in joined
                    if j.get("our_bucket") and j.get("vendor_bucket")]

    out = {"label": label, "n": len(joined),
           "n_score_cvss": len(cvss_pairs),
           "n_bucket":     len(bucket_pairs)}

    if cvss_pairs:
        rho, p = spearmanr([a for a, _ in cvss_pairs], [b for _, b in cvss_pairs])
        out["spearman_score_vs_vendor_cvss"] = {"rho": round(rho, 4),
                                                "p":   float(p),
                                                "n":   len(cvss_pairs)}
    if cvss_pairs2:
        rho2, p2 = spearmanr([a for a, _ in cvss_pairs2], [b for _, b in cvss_pairs2])
        out["spearman_baseline_our_cvss_vs_vendor_cvss"] = {"rho": round(rho2, 4),
                                                            "p":   float(p2),
                                                            "n":   len(cvss_pairs2)}
    if bucket_pairs:
        our   = [a for a, _ in bucket_pairs]
        their = [b for _, b in bucket_pairs]
        out["cohen_kappa_bucket"] = round(_cohen_kappa(our, their), 4)
        # Agreement breakdown
        agree = sum(1 for a, b in bucket_pairs if a == b)
        out["bucket_agreement_rate"] = round(agree / len(bucket_pairs), 4)
        # Distance: how far apart on average (in bucket ranks)
        diffs = [abs(_bucket_to_rank(a) - _bucket_to_rank(b)) for a, b in bucket_pairs]
        out["bucket_mean_abs_distance"] = round(statistics.mean(diffs), 3)
    return out


def per_component(joined):
    out = {}
    for j in joined:
        out.setdefault(j["component"], []).append(j)
    table = []
    for comp, items in out.items():
        table.append({
            "component": comp,
            "cves":      len(items),
            "act":       sum(1 for x in items if x["our_bucket"] == "Act"),
            "attend":    sum(1 for x in items if x["our_bucket"] == "Attend"),
            "trackstar": sum(1 for x in items if x["our_bucket"] == "Track*"),
            "track":     sum(1 for x in items if x["our_bucket"] == "Track"),
            "vendor_cvss_avg": round(statistics.mean(
                x["vendor_cvss"] for x in items if x.get("vendor_cvss")), 2)
                if any(x.get("vendor_cvss") for x in items) else None,
        })
    return sorted(table, key=lambda t: -t["cves"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="eval/results/sc4_report.json")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO)

    rows = _collect_scan_vulns()
    print(f"Scan vulns collected: {len(rows)} (unique CVEs: {len({r['cve'] for r in rows})})")
    print(f"CSAF cache: {csaf_stats()}")

    joined = join_with_csaf(rows)
    print(f"Join with CSAF: {len(joined)} pairs")
    if not joined:
        print("No overlap yet — has the benchmark finished + CSAF fetch completed?")
        return

    overall = compute_metrics(joined, "ALL")
    siemens_only = compute_metrics(
        [j for j in joined if "Siemens ProductCERT" in (j.get("publishers") or [])],
        "Siemens"
    )
    cisa_only = compute_metrics(
        [j for j in joined if "CISA" in (j.get("publishers") or [])],
        "CISA",
    )

    out = {
        "metrics": {"overall": overall, "siemens": siemens_only, "cisa": cisa_only},
        "per_component": per_component(joined)[:30],
        "n_total_pairs": len(joined),
        "n_unique_cves": len({j["cve"] for j in joined}),
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2))

    print()
    print(f"{'subset':<10} {'n':>5} {'ρ(score)':>10} {'κ':>8} {'agree%':>8}")
    for label, m in out["metrics"].items():
        rho = m.get("spearman_score_vs_vendor_cvss", {}).get("rho")
        kappa = m.get("cohen_kappa_bucket")
        agree = m.get("bucket_agreement_rate")
        print(f"{label:<10} {m['n']:>5} "
              f"{rho if rho is not None else '—':>10} "
              f"{kappa if kappa is not None else '—':>8} "
              f"{(agree*100 if agree is not None else '—'):>8}")
    print(f"\nReport saved: {out_path}")


if __name__ == "__main__":
    main()
