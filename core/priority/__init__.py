"""
Prioritisation framework — hybrid SSVC bucket + weighted intra-bucket score.

Public entry point: prioritize(report, profile) → annotated report.

Each vulnerability in report["vulnerable_components"][*]["vulns"][*] receives:

    "priority": {
        "bucket":    "Act" | "Attend" | "Track*" | "Track",
        "score":     0.0–1.0,
        "rationale": "Act: exploitation=Active, exposure=Open, …",
        "breakdown": { "ssvc_inputs": {…}, "formula_terms": {…} },
    }

Each vulnerable component also gets:
    "priority_bucket":    highest bucket across its vulns
    "priority_score_max": max intra-bucket score across its vulns

Report-level aggregate:
    report["priority"] = {
        "profile": {…},
        "buckets": {"Act": n, "Attend": n, "Track*": n, "Track": n},
    }
"""
from typing import Union

from .models import ContextProfile, Priority, PriorityBreakdown, SSVCInputs
from .profiles import DEFAULT_PRESET, PRESETS, load_profile, load_yaml
from .scoring import score
from .ssvc import bucket, evaluate, rationale

# Most-to-least urgent. Used by callers to compare buckets via index.
BUCKET_ORDER = ["Act", "Attend", "Track*", "Track"]

_ProfileLike = Union[None, str, dict, ContextProfile]


def prioritize(report: dict, profile: _ProfileLike = None) -> dict:
    """Annotate every vulnerability in *report* with SSVC bucket + score.

    The report dict is mutated in place AND returned for convenience.
    """
    p = load_profile(profile)
    bucket_counts = {b: 0 for b in BUCKET_ORDER}

    for comp in report.get("vulnerable_components", []):
        for v in comp.get("vulns", []):
            inputs = evaluate(p, v)
            bkt    = bucket(inputs)
            sc, terms = score(p, v)

            v["priority"] = Priority(
                bucket=bkt,
                score=sc,
                rationale=rationale(inputs, bkt),
                breakdown=PriorityBreakdown(
                    ssvc_inputs=inputs,
                    formula_terms=terms,
                ),
            ).model_dump()
            bucket_counts[bkt] += 1

        if comp.get("vulns"):
            buckets = [v["priority"]["bucket"] for v in comp["vulns"]]
            comp["priority_bucket"] = min(buckets, key=BUCKET_ORDER.index)
            comp["priority_score_max"] = max(
                v["priority"]["score"] for v in comp["vulns"]
            )

    report["priority"] = {
        "profile": p.to_jsonable(),
        "buckets": bucket_counts,
    }
    return report


__all__ = [
    "BUCKET_ORDER",
    "ContextProfile",
    "DEFAULT_PRESET",
    "PRESETS",
    "Priority",
    "PriorityBreakdown",
    "SSVCInputs",
    "load_profile",
    "load_yaml",
    "prioritize",
]
