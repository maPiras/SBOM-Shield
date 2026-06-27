"""
SBOM generation via Syft (Anchore).

Syft is the secondary SBOM tool for SBOM-Shield: it runs after cdxgen and
fills detection gaps in ecosystems where Syft has stronger coverage
(OS packages, container layers, certain Go / Rust binaries). Components
that Syft finds and cdxgen missed are merged in by `core.sbom_merger`.

Each component produced here is tagged with a `sbom-shield:source=syft`
property so attribution is preserved through the merge.
"""
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

_TIMEOUT = 300

_SOURCE_PROPERTY = "sbom-shield:source"
_SOURCE_VALUE = "syft"


def is_available() -> bool:
    """Return True when the syft binary is reachable on PATH."""
    return shutil.which("syft") is not None


def generate(target_dir: str | Path) -> dict:
    """
    Run Syft on *target_dir* and return the resulting CycloneDX JSON dict.

    Raises
    ------
    FileNotFoundError   If *target_dir* does not exist.
    RuntimeError        If syft exits non-zero or produces no output file.
    """
    target_dir = Path(target_dir).resolve()
    if not target_dir.exists():
        raise FileNotFoundError(f"Directory not found: {target_dir}")

    if not is_available():
        raise RuntimeError("syft not found on PATH")

    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "sbom.json"

        result = subprocess.run(
            ["syft", str(target_dir), "-o", f"cyclonedx-json={out_path}"],
            capture_output=True, text=True, timeout=_TIMEOUT,
        )

        if result.returncode != 0:
            raise RuntimeError(f"syft failed: {result.stderr[:500]}")
        if not out_path.exists():
            raise RuntimeError("syft did not produce an SBOM output file")

        sbom = json.loads(out_path.read_text())
        _tag_components(sbom)
        logger.info(
            f"SBOM generated: {len(sbom.get('components', []))} component(s) "
            f"[syft, CycloneDX {sbom.get('specVersion', '?')}]"
        )
        return sbom


def _tag_components(sbom: dict) -> None:
    """Stamp every component with a `sbom-shield:source=syft` property."""
    for comp in sbom.get("components", []):
        props = comp.setdefault("properties", [])
        if any(p.get("name") == _SOURCE_PROPERTY for p in props):
            continue
        props.append({"name": _SOURCE_PROPERTY, "value": _SOURCE_VALUE})
