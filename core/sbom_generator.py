"""
SBOM generation orchestrator.

cdxgen is the primary tool; Syft is invoked as a secondary scanner to fill
gaps in ecosystems where cdxgen is weaker (OS packages, certain binaries).
The two CycloneDX outputs are merged via `core.sbom_merger` with cdxgen
winning on conflict.

CycloneDX is the chosen output format because OSV and NVD correlate
vulnerabilities via Package URLs (PURLs), which CycloneDX carries as a
first-class field.
"""
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from core import cdxgen_runner, syft_runner
from core.sbom_merger import merge as merge_sboms, MergeStats

logger = logging.getLogger(__name__)


@dataclass
class GenerationResult:
    sbom: dict
    cdxgen_used: bool
    syft_used: bool
    merge_stats: MergeStats | None   # None when only one tool ran


def generate_sbom(
    target_dir: str | Path,
    *,
    syft_fallback: bool = True,
    online: bool = False,
) -> GenerationResult:
    """
    Generate a CycloneDX SBOM for *target_dir*.

    Parameters
    ----------
    syft_fallback : bool, default True
        If True and Syft is installed, runs Syft after cdxgen and merges in
        any components Syft found that cdxgen missed. If False, Syft is
        skipped entirely.
    online : bool, default False
        If True, cdxgen runs in online mode (deeper transitive resolution
        via public registries). Default offline keeps the run safe for
        proprietary / pre-release customer code.

    Raises
    ------
    FileNotFoundError   If *target_dir* does not exist.
    RuntimeError        If cdxgen is unavailable or fails. Syft failure is
                        downgraded to a warning — cdxgen output is still
                        returned.
    """
    target_dir = Path(target_dir).resolve()
    if not target_dir.exists():
        raise FileNotFoundError(f"Directory not found: {target_dir}")

    primary = cdxgen_runner.generate(target_dir, online=online)

    if not syft_fallback:
        return GenerationResult(sbom=primary, cdxgen_used=True, syft_used=False, merge_stats=None)

    if not syft_runner.is_available():
        logger.info("Syft fallback skipped: syft not installed")
        return GenerationResult(sbom=primary, cdxgen_used=True, syft_used=False, merge_stats=None)

    try:
        secondary = syft_runner.generate(target_dir)
    except Exception as exc:
        # Syft is the safety net, not the primary — never let its failure
        # block the scan when cdxgen already produced an SBOM.
        logger.warning(f"Syft fallback failed, continuing with cdxgen-only SBOM: {exc}")
        return GenerationResult(sbom=primary, cdxgen_used=True, syft_used=False, merge_stats=None)

    merged, stats = merge_sboms(primary, secondary)
    return GenerationResult(sbom=merged, cdxgen_used=True, syft_used=True, merge_stats=stats)


def load_sbom(path: str | Path) -> dict:
    """
    Load a pre-generated CycloneDX JSON SBOM from *path*.

    Useful in CI pipelines where SBOM generation has already happened in a
    previous step. No validation is performed here — `parse_sbom` will raise
    if the file is not valid CycloneDX.
    """
    return json.loads(Path(path).read_text())
