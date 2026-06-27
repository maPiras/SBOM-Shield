"""
Intra-bucket weighted scoring formula.

Two vulnerabilities falling in the same SSVC bucket are ranked by:

    score = α·(CVSS/10) + β·EPSS + γ·KEV + δ·criticality_weight + ε·exploit_avail

* CVSS and EPSS use their continuous values (vs. the discrete thresholds
  consumed by SSVC) — this is the only "leak" of the same signal across
  layers, and it is intentional: SSVC buckets coarsely, scoring orders within
  the bucket.
* update_cadence_days is NOT in the formula; it lives only in the SSVC impact
  level (see ssvc.py module docstring).
* Weights below are W1 defaults and WILL be tuned in W3 via Spearman/κ vs
  Siemens ProductCERT CSAF on the 50-component candidate set.

Returns (score, terms_dict) so the caller can attach a full breakdown to the
report — required for the "explainable prioritisation" story in the thesis
and the dashboard's per-finding rationale display.
"""
from .models import ContextProfile

ALPHA   = 0.30   # CVSS                — base technical severity
BETA    = 0.35   # EPSS                — likelihood of exploitation in the wild
GAMMA   = 0.15   # KEV bonus           — currently exploited (CISA-confirmed)
DELTA   = 0.15   # context multiplier  — criticality only (not cadence)
EPSILON = 0.05   # exploit_available   — VulDB-reported public exploit

_CRIT_WEIGHT = {
    "safety_critical": 1.00,
    "production":      0.75,
    "lab":             0.40,
    "dev":             0.20,
}


def score(profile: ContextProfile, vuln: dict) -> tuple[float, dict[str, float]]:
    cvss = (vuln.get("cvss") or 0.0) / 10.0
    epss = vuln.get("epss") or 0.0
    kev  = 1.0 if (vuln.get("source") == "CISA-KEV" or vuln.get("in_kev")) else 0.0
    ctx  = _CRIT_WEIGHT[profile.criticality]
    expl = 1.0 if vuln.get("exploit_available") else 0.0

    terms = {
        "cvss_term": round(ALPHA   * cvss, 4),
        "epss_term": round(BETA    * epss, 4),
        "kev_term":  round(GAMMA   * kev,  4),
        "ctx_term":  round(DELTA   * ctx,  4),
        "expl_term": round(EPSILON * expl, 4),
    }
    return round(sum(terms.values()), 4), terms
