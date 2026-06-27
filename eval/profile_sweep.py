#!/usr/bin/env python3
"""
SC5 — Context-profile sensitivity ("same SBOM, four profiles" demonstration).

Three views, all computed without network or re-scan by re-running only the SSVC
tree + intra-bucket score on the stored vulnerability signals:

  (a) Empirical sweep   — bucket distribution of the fixed 1509-finding benchmark
                          set under each of the four built-in profiles.
  (b) Controlled matrix — one fixed CVSS-9.8 finding, bucket as a function of
                          (profile x exploitation tier) — shows the full Track->Act
                          range the framework spans when exploitation is present.
  (c) Score shift       — mean intra-bucket score of the same findings under each
                          profile, showing context changes the ranking even when
                          it does not change the bucket.

Output: eval/results/profile_sweep.json + console tables.
"""
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core.priority import prioritize           # noqa: E402

RESULTS = ROOT / "eval" / "results"
POOL = ["zephyr", "esp-idf", "apollo", "autoware_universe", "RIOT", "CarPlayCore",
        "OpenPLC_v3", "FreeRTOS-Plus-TCP", "mongoose", "mosquitto", "open62541",
        "lvgl", "iceoryx", "busybox"]
PROFILES = ["production_ot", "safety_critical_ot", "lab_research", "automotive_infotainment"]
BUCKETS = ["Act", "Attend", "Track*", "Track"]


def _bucket(v):
    pr = v.get("priority", {})
    return pr.get("bucket") if isinstance(pr, dict) else getattr(pr, "bucket", None)


def _score(v):
    pr = v.get("priority", {})
    return pr.get("score") if isinstance(pr, dict) else getattr(pr, "score", None)


def main():
    # ── (a) empirical sweep ──────────────────────────────────────────────────
    sweep = {p: {b: 0 for b in BUCKETS} for p in PROFILES}
    n_total = 0
    for repo in POOL:
        f = RESULTS / f"{repo}.json"
        if not f.exists():
            continue
        base = json.loads(f.read_text())
        n_total += sum(len(c.get("vulns", [])) for c in base.get("vulnerable_components", []))
        for p in PROFILES:
            rep = json.loads(f.read_text())
            prioritize(rep, p)
            for c in rep.get("vulnerable_components", []):
                for v in c.get("vulns", []):
                    b = _bucket(v)
                    if b in sweep[p]:
                        sweep[p][b] += 1

    # ── (b) controlled sensitivity matrix ────────────────────────────────────
    def mk(cvss, epss, kev, exploit):
        return {"vulnerable_components": [{"name": "demo", "vulns": [
            {"id": "CVE-0000-0000", "severity": "CRITICAL", "cvss": cvss, "epss": epss,
             "in_kev": kev, "exploit_available": exploit}]}]}
    tiers = [("None", dict(cvss=9.8, epss=0.05, kev=False, exploit=False)),
             ("Public PoC", dict(cvss=9.8, epss=0.55, kev=False, exploit=True)),
             ("Active (KEV)", dict(cvss=9.8, epss=0.85, kev=True, exploit=True))]
    matrix = {}
    for tname, sig in tiers:
        matrix[tname] = {}
        for p in PROFILES:
            r = mk(**sig)
            prioritize(r, p)
            matrix[tname][p] = _bucket(r["vulnerable_components"][0]["vulns"][0])

    # ── (c) intra-bucket score shift ─────────────────────────────────────────
    score_stats = {}
    for p in PROFILES:
        scores = []
        for repo in POOL:
            f = RESULTS / f"{repo}.json"
            if not f.exists():
                continue
            rep = json.loads(f.read_text())
            prioritize(rep, p)
            for c in rep.get("vulnerable_components", []):
                for v in c.get("vulns", []):
                    s = _score(v)
                    if s is not None:
                        scores.append(s)
        if scores:
            score_stats[p] = {"mean": round(statistics.mean(scores), 3),
                              "median": round(statistics.median(scores), 3),
                              "max": round(max(scores), 3)}

    # ── print ────────────────────────────────────────────────────────────────
    print(f"(a) Bucket sweep over {n_total} findings held constant:\n")
    hdr = f"{'profile':24}" + "".join(f"{b:>9}" for b in BUCKETS)
    print(hdr + "\n" + "-" * len(hdr))
    for p in PROFILES:
        print(f"{p:24}" + "".join(f"{sweep[p][b]:>9}" for b in BUCKETS))

    print("\n(b) Controlled: same CVSS-9.8 finding, bucket by (exploitation x profile):\n")
    print(f"{'exploitation':14}" + "".join(f"{p.split('_')[0][:9]:>11}" for p in PROFILES))
    for tname in matrix:
        print(f"{tname:14}" + "".join(f"{matrix[tname][p]:>11}" for p in PROFILES))

    print("\n(c) Intra-bucket score, same findings under each profile:")
    for p, s in score_stats.items():
        print(f"  {p:24} mean={s['mean']} median={s['median']} max={s['max']}")

    out = {"n_findings": n_total, "sweep": sweep,
           "controlled_matrix": matrix, "score_stats": score_stats}
    (RESULTS / "profile_sweep.json").write_text(json.dumps(out, indent=2))
    print(f"\n→ {RESULTS / 'profile_sweep.json'}")


if __name__ == "__main__":
    main()
