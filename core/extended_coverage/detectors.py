"""
OT/ICS scan orchestrator.

Runs all component sub-detectors in parallel and assembles the final
OTScanResult.  Detection logic lives in a focused module:

  scanners.py  — component detectors (protocols, RTOS, BSP, device desc)
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from core.noise_filter.call_verifier import verify_calls
from .models import OTComponent, OTScanResult, purl_for
from .scanners import (
    FileIndex,
    detect_bsp,
    detect_build_manifest,
    detect_device_desc,
    detect_protocols,
    detect_rtos,
)
from .build_detectors import (
    detect_autoconf,
    detect_compile_commands,
    detect_cmake_link_libs,
    detect_esp_idf_manifest,
    detect_zephyr_manifest,
)
from .elf_detector import detect_elf_binaries
from .version_extractor import enrich_versions

logger = logging.getLogger(__name__)

# Display order for categories in the final report (lower = earlier)
_SORT_ORDER = {
    "DEVICE_DESC":    0,
    "RUNTIME":        1,
    "RTOS":           2,
    "FIELDBUS":       3,
    "PROTOCOL_STACK": 4,
    "SCADA_HMI":      5,
    "BSP_HAL":        6,
    "UNKNOWN":        99,
}

# Map of logical name → detector function (used to tag futures for logging)
_COMPONENT_DETECTORS = {
    "protocols":         detect_protocols,
    "rtos":              detect_rtos,
    "bsp":               detect_bsp,
    "device_desc":       detect_device_desc,
    "build_manifest":    detect_build_manifest,
    "autoconf":          detect_autoconf,
    "compile_commands":  detect_compile_commands,
    "cmake_link_libs":   detect_cmake_link_libs,
    "esp_idf_manifest":  detect_esp_idf_manifest,
    "zephyr_manifest":   detect_zephyr_manifest,
    "elf_binaries":      detect_elf_binaries,
}


def run(target: str | Path) -> OTScanResult:
    """
    Analyse *target* with all OT sub-detectors running in parallel.

    Steps
    -----
    1. Submit all component detectors to a thread pool.
    2. Collect results; log per-detector counts and any errors.
    3. Deduplicate components by (category, name) key, merging evidence and
       preferring HIGH confidence / known versions when available.
    4. Sort components by category display order, then name.

    Returns an OTScanResult ready for .to_dict() serialisation.
    """
    root   = Path(target).resolve()
    result = OTScanResult(target=str(root))

    if not root.exists():
        logger.warning("extended_coverage: path not found: %s", root)
        return result

    # Build the file index once — single directory walk, shared content
    # cache.  All detectors receive the same index so no file is read
    # from disk more than once.
    idx = FileIndex(root)
    logger.debug(
        "OT file index: %d files (%d extensions)",
        len(idx.all_files), len(idx.by_ext),
    )

    all_comps: list[OTComponent] = []

    with ThreadPoolExecutor(max_workers=6) as pool:
        # Submit component detectors
        comp_futs = {
            pool.submit(fn, idx): name
            for name, fn in _COMPONENT_DETECTORS.items()
        }

        # Collect component results
        for fut in as_completed(comp_futs):
            name = comp_futs[fut]
            try:
                found = fut.result()
                logger.debug("OT [%s]: %d component(s)", name, len(found))
                all_comps.extend(found)
            except Exception as exc:                      # noqa: BLE001
                logger.warning("OT [%s] error: %s", name, exc)

    # ── Deduplication ─────────────────────────────────────────────────────────
    # Multiple detectors can find the same component (e.g. FreeRTOS spotted by
    # both a CMakeLists.txt and a FreeRTOSConfig.h rule).  Merge their evidence.
    deduped: dict[str, OTComponent] = {}
    for comp in all_comps:
        k = comp.key                  # (category, name) composite key
        if k not in deduped:
            deduped[k] = comp
        else:
            existing = deduped[k]
            existing.matches.extend(comp.matches)
            # Upgrade confidence if this hit is stronger
            if comp.confidence == "HIGH" and existing.confidence != "HIGH":
                existing.confidence = "HIGH"
            # Prefer a concrete version over None
            if comp.version and not existing.version:
                existing.version = comp.version
                existing.purl    = comp.purl

    # ── Build-manifest cross-reference ────────────────────────────────────
    # If a component has both an import match and a build_manifest match it
    # was fetched remotely (CMake FetchContent, west.yml, git submodule, etc.)
    # Upgrade import matches from "unknown" → "remote" unless already "vendored"
    # (presence in the repo tree takes precedence over remote evidence).
    for comp in deduped.values():
        if any(m.detection_type == "build_manifest" for m in comp.matches):
            for m in comp.matches:
                if m.detection_type == "import" and m.source_type == "unknown":
                    m.source_type = "remote"

    # ── Version enrichment ────────────────────────────────────────────────
    # Fill missing versions from CMakeCache.txt, .pc files, hex macros, and
    # embedded binary strings.  Must run after dedup so each component is
    # enriched at most once.
    n_ver = enrich_versions(list(deduped.values()), root)
    if n_ver:
        logger.debug("version_extractor: %d component(s) enriched", n_ver)

    # ── Call-site verification ────────────────────────────────────────────
    # Tree-sitter walk: confirm components are actually called in C/C++ source.
    # Upgrades MEDIUM → HIGH confidence; appends api_call DetectionMatch evidence.
    verify_calls(list(deduped.values()), root)

    result.components = sorted(
        deduped.values(),
        key=lambda c: (_SORT_ORDER.get(c.category, 99), c.name),
    )

    logger.info("extended_coverage: %d component(s)", len(result.components))
    return result
