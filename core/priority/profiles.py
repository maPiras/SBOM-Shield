"""
Built-in ContextProfile presets + YAML loader.

The GUI offers the three presets below as one-click defaults; the underlying
fields are individually editable in the scan modal, and the resulting profile
is persisted with the scan / track row as JSON.
"""
from pathlib import Path
from typing import Union

import yaml

from .models import ContextProfile

PROFILES_DIR = Path(__file__).parent / "profiles"

# ─── Built-in presets ────────────────────────────────────────────────────────
PRESETS: dict[str, ContextProfile] = {
    "production_ot": ContextProfile(
        name="production_ot",
        exposure="network",
        criticality="production",
        update_cadence_days=365,
    ),
    "safety_critical_ot": ContextProfile(
        name="safety_critical_ot",
        exposure="local",
        criticality="safety_critical",
        update_cadence_days=1825,
    ),
    "lab_research": ContextProfile(
        name="lab_research",
        exposure="local",
        criticality="lab",
        update_cadence_days=30,
    ),
    "automotive_infotainment": ContextProfile(
        name="automotive_infotainment",
        exposure="network",
        criticality="production",
        update_cadence_days=180,
    ),
}

DEFAULT_PRESET = "production_ot"


def load_profile(value: Union[None, str, dict, ContextProfile]) -> ContextProfile:
    """Coerce any of {None, preset name, dict, ContextProfile} into a profile.

    Unknown preset names fall back to DEFAULT_PRESET silently — this avoids
    breaking the pipeline when the dashboard hands us a stale label.
    """
    if value is None:
        return PRESETS[DEFAULT_PRESET]
    if isinstance(value, ContextProfile):
        return value
    if isinstance(value, str):
        return PRESETS.get(value, PRESETS[DEFAULT_PRESET])
    if isinstance(value, dict):
        return ContextProfile.model_validate(value)
    raise TypeError(f"Cannot coerce {type(value).__name__} to ContextProfile")


def load_yaml(path: Path) -> ContextProfile:
    with path.open() as f:
        data = yaml.safe_load(f) or {}
    return ContextProfile.model_validate(data)
