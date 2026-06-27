"""
Pydantic schemas for the prioritisation framework.

ContextProfile        — three-axis embedded SCA context (replaces Purdue level).
SSVCInputs            — discrete SSVC-tree inputs evaluated per vulnerability.
PriorityBreakdown     — full audit trail (SSVC inputs + formula terms).
Priority              — final per-vuln output: bucket + score + rationale.
"""
from typing import Literal

from pydantic import BaseModel, Field

Exposure        = Literal["airgapped", "local", "network"]
Criticality     = Literal["safety_critical", "production", "lab", "dev"]
SSVCBucket      = Literal["Track", "Track*", "Attend", "Act"]
SSVCExploit     = Literal["None", "Public PoC", "Active"]
SSVCExposure    = Literal["Small", "Controlled", "Open"]
SSVCUtility     = Literal["Laborious", "Efficient", "Super Effective"]
SSVCImpact      = Literal["Low", "Medium", "High", "Very High"]

# Categorical → numeric severity inferred from CVSS, used as bucket-tie input.
_CVSS_VERY_HIGH_THRESHOLD = 9.0
_CVSS_HIGH_THRESHOLD      = 7.0


class ContextProfile(BaseModel):
    """Per-scan operational context. Drives the SSVC bucketing and the
    intra-bucket weighted score."""
    name: str                            = Field(default="custom",
                                                description="Profile label, free-form.")
    exposure: Exposure                   = Field(default="network")
    criticality: Criticality             = Field(default="production")
    update_cadence_days: int             = Field(default=90, ge=1, le=10000,
                                                description="Days between firmware/software updates "
                                                            "in the deployed environment.")

    def to_jsonable(self) -> dict:
        return self.model_dump()


class SSVCInputs(BaseModel):
    exploitation: SSVCExploit
    exposure:     SSVCExposure
    utility:      SSVCUtility
    impact:       SSVCImpact


class PriorityBreakdown(BaseModel):
    ssvc_inputs:   SSVCInputs
    formula_terms: dict[str, float]


class Priority(BaseModel):
    bucket:    SSVCBucket
    score:     float
    rationale: str
    breakdown: PriorityBreakdown
