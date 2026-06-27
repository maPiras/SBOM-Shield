"""
SSVC decision tree — variant of CISA's Deployer profile.

Inputs are discretised from raw vulnerability + context signals; the tree
returns a categorical bucket (Track / Track* / Attend / Act). Intra-bucket
ordering is handled separately by `scoring.py`.

Design choices recorded:

* update_cadence_days is consumed HERE (impact level) and NOT in the scoring
  formula, to avoid double-counting (see notes/priority_gui_track_update.txt
  §"Why update_cadence_days appears only in SSVC impact").
* Exploitation: KEV → Active; VulDB exploit_available OR EPSS≥0.5 → Public PoC.
* Utility: a function of EPSS and Exploitation (no "automatable" signal yet).
* Impact: criticality drives the base level; long update cadence + high CVSS
  bumps the level by one notch.
"""
from .models import (
    ContextProfile,
    SSVCBucket,
    SSVCExploit,
    SSVCExposure,
    SSVCImpact,
    SSVCInputs,
    SSVCUtility,
)

_EPSS_ACTIVE_THRESHOLD     = 0.7
_EPSS_PUBLIC_POC_THRESHOLD = 0.5
_EPSS_EFFICIENT_THRESHOLD  = 0.3

_EXPOSURE_MAP: dict[str, SSVCExposure] = {
    "airgapped": "Small",
    "local":     "Controlled",
    "network":   "Open",
}

_IMPACT_BASE: dict[str, SSVCImpact] = {
    "safety_critical": "Very High",
    "production":      "High",
    "lab":             "Medium",
    "dev":             "Low",
}
_IMPACT_ORDER = ["Low", "Medium", "High", "Very High"]


def _exploitation(vuln: dict) -> SSVCExploit:
    if vuln.get("source") == "CISA-KEV" or vuln.get("in_kev"):
        return "Active"
    if vuln.get("exploit_available"):
        return "Public PoC"
    epss = vuln.get("epss") or 0.0
    if epss >= _EPSS_PUBLIC_POC_THRESHOLD:
        return "Public PoC"
    return "None"


def _exposure(profile: ContextProfile) -> SSVCExposure:
    return _EXPOSURE_MAP[profile.exposure]


def _utility(vuln: dict, exploitation: SSVCExploit) -> SSVCUtility:
    epss = vuln.get("epss") or 0.0
    if epss >= _EPSS_ACTIVE_THRESHOLD and exploitation != "None":
        return "Super Effective"
    if epss >= _EPSS_EFFICIENT_THRESHOLD:
        return "Efficient"
    return "Laborious"


def _impact(profile: ContextProfile, vuln: dict) -> SSVCImpact:
    base: SSVCImpact = _IMPACT_BASE[profile.criticality]
    cvss = vuln.get("cvss") or 0.0
    # Firmware-frozen device (>1 year cadence) with high CVSS → impact bumped
    # by one notch. This is the *only* place update_cadence_days enters the
    # framework — see module docstring for the no-double-counting rationale.
    if profile.update_cadence_days > 365 and cvss >= 7.0:
        idx = min(_IMPACT_ORDER.index(base) + 1, len(_IMPACT_ORDER) - 1)
        base = _IMPACT_ORDER[idx]    # type: ignore[assignment]
    return base


def evaluate(profile: ContextProfile, vuln: dict) -> SSVCInputs:
    expl = _exploitation(vuln)
    return SSVCInputs(
        exploitation=expl,
        exposure=_exposure(profile),
        utility=_utility(vuln, expl),
        impact=_impact(profile, vuln),
    )


def bucket(inputs: SSVCInputs) -> SSVCBucket:
    """Decide the SSVC bucket from the four discrete inputs.

    The tree is a simplified CISA-Deployer mapping — exact branches are
    documented in notes/priority_gui_track_update.txt §"SSVC tree branches".
    """
    e, x, u, i = inputs.exploitation, inputs.exposure, inputs.utility, inputs.impact

    if e == "Active":
        if i in ("Very High", "High") or x == "Open":
            return "Act"
        if i == "Medium" or x == "Controlled":
            return "Attend"
        return "Track*"

    if e == "Public PoC":
        if i == "Very High" and x == "Open":
            return "Act"
        if i in ("Very High", "High") and x != "Small":
            return "Attend"
        if u == "Super Effective":
            return "Attend"
        if i == "Low" and x == "Small":
            return "Track"
        return "Track*"

    # e == "None"
    if i == "Very High" and x == "Open":
        return "Attend"
    if u == "Super Effective":
        return "Track*"
    if i in ("Very High", "High") and x != "Small":
        return "Track*"
    return "Track"


def rationale(inputs: SSVCInputs, bkt: SSVCBucket) -> str:
    return (
        f"{bkt}: exploitation={inputs.exploitation}, exposure={inputs.exposure}, "
        f"utility={inputs.utility}, impact={inputs.impact}"
    )
