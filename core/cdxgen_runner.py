"""
SBOM generation via cdxgen (OWASP CycloneDX Generator).

cdxgen is the primary SBOM tool for SBOM-Shield because it has deeper
language coverage for the project's target stack — C/C++ (CMake, Conan),
Python, JavaScript, Java — and emits richer CycloneDX evidence than Syft.

Two operation modes:
  - offline (default): manifest-only analysis, no dependency installation,
    no external registry lookups beyond what is strictly required to build
    PURLs. Safe for proprietary / pre-release customer code.
  - online (--online-resolution): drops the technique restriction so cdxgen
    can perform deeper transitive resolution. Use only on public repos /
    benchmarks where leaking package names to public registries is acceptable.

In both modes cdxgen is invoked with --no-install-deps so it never mutates
the scanned tree (no `npm install`, no `pip install`).
"""
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# cdxgen first-run on a multi-language repo can take several minutes once
# manifest analysis crawls every lockfile. 600 s is the upper bound for
# realistic project sizes.
_TIMEOUT = 600

# CycloneDX spec version emitted. cdxgen 12.x defaults to 1.7; we pin 1.5
# so the output stays comparable with the rest of the pipeline (sbom_parser,
# stored reports, dashboard).
_SPEC_VERSION = "1.5"

_SOURCE_PROPERTY = "sbom-shield:source"
_SOURCE_VALUE = "cdxgen"


def is_available() -> bool:
    """Return True when the cdxgen binary is reachable on PATH."""
    return shutil.which("cdxgen") is not None


def generate(target_dir: str | Path, *, online: bool = False) -> dict:
    """
    Run cdxgen on *target_dir* and return the resulting CycloneDX JSON dict.

    Each component in the output is tagged with a `sbom-shield:source=cdxgen`
    property so that downstream merging and reporting can attribute findings
    back to the originating tool.

    Raises
    ------
    FileNotFoundError   If *target_dir* does not exist.
    RuntimeError        If cdxgen exits non-zero or produces no output file.
    """
    target_dir = Path(target_dir).resolve()
    if not target_dir.exists():
        raise FileNotFoundError(f"Directory not found: {target_dir}")

    if not is_available():
        raise RuntimeError("cdxgen not found on PATH")

    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "bom.json"

        cmd = [
            "cdxgen",
            "-o", str(out_path),
            "--spec-version", _SPEC_VERSION,
            "--no-install-deps",
            "--no-validate",
        ]
        if not online:
            # Manifest-only keeps the run offline-safe: no source-code analysis,
            # no binary scans, no registry calls beyond PURL construction.
            cmd += ["--technique", "manifest-analysis"]
        cmd.append(str(target_dir))

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_TIMEOUT,
        )

        if result.returncode != 0:
            raise RuntimeError(f"cdxgen failed: {result.stderr[:500]}")
        if not out_path.exists():
            raise RuntimeError("cdxgen did not produce an SBOM output file")

        sbom = json.loads(out_path.read_text())
        _tag_components(sbom)
        logger.info(
            f"SBOM generated: {len(sbom.get('components', []))} component(s) "
            f"[cdxgen, CycloneDX {sbom.get('specVersion', '?')}, "
            f"{'online' if online else 'offline'}]"
        )
        return sbom


def _tag_components(sbom: dict) -> None:
    """Stamp every component with a `sbom-shield:source=cdxgen` property."""
    for comp in sbom.get("components", []):
        props = comp.setdefault("properties", [])
        # Don't double-tag if the runner is somehow called twice.
        if any(p.get("name") == _SOURCE_PROPERTY for p in props):
            continue
        props.append({"name": _SOURCE_PROPERTY, "value": _SOURCE_VALUE})
