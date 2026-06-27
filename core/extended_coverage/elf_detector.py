"""
Augment-layer ELF binary detector.

Analyses ELF/AXF firmware images using readelf(1).  One evidence source per
pass:

  .debug_str section — DWARF string table: DW_AT_comp_dir paths expose
                       component names from the build directory structure:
                         ESP-IDF   build/{component}/
                         CMake     CMakeFiles/{target}.dir/
                         Zephyr    modules/lib/{name}/

A component is only emitted if it either:
  (a) matches a known OT/ICS library in the fragment table, OR
  (b) carries an explicit version string extracted from its path segment
      (e.g. newlib_xtensa-2.2.0, FreeRTOSV10.4.1)

This conservative rule avoids flooding the report with LOW-confidence
framework internals (esp_ringbuf, app_update, cxx, …) that cannot be
queried for CVEs.

detect_elf_binaries(idx) -> list[OTComponent]

Returns [] silently when readelf is not on PATH or no ELF/AXF files exist.
"""
from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from typing import Optional

from .models import OTComponent
from .scanners import FileIndex, _dm
from .build_detectors import _norm, _match_name_to_known, _make_component

logger = logging.getLogger(__name__)

_ELF_EXTS    = frozenset({".elf", ".axf"})
_MAX_ELF     = 10          # cap: avoid spending minutes on huge firmware trees
_MAX_ELF_MB  = 50          # skip individual ELFs larger than this
_DBG_TIMEOUT = 120         # seconds allowed for readelf --debug-dump=str

# Offset-prefixed line from readelf string / section dumps:
#   "  [    0]  the string content"
_STRLINE_RX = re.compile(r'^\s*\[[\s0-9a-fA-F]+\]\s+(.+)$')

# Build-directory component-name patterns
_BUILD_RX  = re.compile(r'/build/([a-zA-Z][a-zA-Z0-9_\-]+)(?:/|$)')
_CMAKE_RX  = re.compile(r'CMakeFiles/([a-zA-Z][a-zA-Z0-9_\-]+)\.dir')
_ZEPHYR_RX = re.compile(r'/modules/(?:lib|hal|crypto)/([a-zA-Z][a-zA-Z0-9_\-]+)')

# Version embedded in a path segment:  lwip-2.1.3  /  FreeRTOSV10.4.1  / newlib-2.2.0
_PATHVER_RX = re.compile(r'[-_Vv]([\d]+\.[\d]+(?:\.[\d]+)?)')

_READELF_OK: Optional[bool] = None


def _readelf_available() -> bool:
    global _READELF_OK
    if _READELF_OK is None:
        try:
            subprocess.run(["readelf", "--version"], capture_output=True, timeout=5)
            _READELF_OK = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            _READELF_OK = False
    return _READELF_OK


def _run_readelf(args: list[str], path: Path, timeout: int = 30) -> str:
    try:
        r = subprocess.run(
            ["readelf"] + args + [str(path)],
            capture_output=True, text=True,
            timeout=timeout, errors="replace",
        )
        return r.stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("readelf %s: %s", path.name, exc)
        return ""


# ── .debug_str parsing ────────────────────────────────────────────────────────

def _ver_from_path_segment(segment: str, component: str) -> Optional[str]:
    """Try to extract a version from a single path segment."""
    m = re.search(
        re.escape(component) + r'[-_Vv]+([\d]+\.[\d]+(?:\.[\d]+)?)',
        segment, re.I,
    )
    if m:
        return m.group(1)
    if component.lower() in segment.lower():
        mv = _PATHVER_RX.search(segment)
        if mv:
            return mv.group(1)
    return None


def _extract_candidates(output: str) -> list[tuple[str, str, Optional[str]]]:
    """
    Parse readelf --debug-dump=str output.

    Returns list of (norm_key, display_name, version_or_None).
    Only yields entries where the component name is ≥ 3 chars.
    """
    seen: set[str] = set()
    results: list[tuple[str, str, Optional[str]]] = []

    for line in output.splitlines():
        m = _STRLINE_RX.match(line)
        if not m:
            continue
        s = m.group(1).strip()
        if '/' not in s:        # not a path — skip type names, function names, etc.
            continue

        for pattern in (_BUILD_RX, _CMAKE_RX, _ZEPHYR_RX):
            for pm in pattern.finditer(s):
                name = pm.group(1)
                if len(name) < 3:
                    continue
                key = _norm(name)
                if key in seen:
                    continue
                seen.add(key)
                ver: Optional[str] = None
                for part in Path(s).parts:
                    ver = _ver_from_path_segment(part, name)
                    if ver:
                        break
                results.append((key, name, ver))

    return results


# ── Main detector ─────────────────────────────────────────────────────────────

def detect_elf_binaries(idx: FileIndex) -> list[OTComponent]:
    """
    Detect components from ELF/AXF firmware binaries via readelf.

    Only emits a component when it is either:
      - matched as a known OT/ICS library via _match_name_to_known, OR
      - the path segment contains an explicit version string.

    This conservative filter avoids injecting ~25+ ESP-IDF / Zephyr
    framework internals that have no standalone CVE exposure.
    """
    if not _readelf_available():
        logger.debug("elf_detector: readelf not on PATH, skipping")
        return []

    elf_files = [p for p in idx.all_files if p.suffix in _ELF_EXTS]
    if not elf_files:
        return []

    found: dict[str, OTComponent] = {}

    for path in elf_files[:_MAX_ELF]:
        # Skip suspiciously large files to avoid memory / time issues
        try:
            if path.stat().st_size > _MAX_ELF_MB * 1024 * 1024:
                logger.debug("elf_detector: skipping large binary %s", path.name)
                continue
        except OSError:
            continue

        rel = idx.rel(path)
        logger.debug("elf_detector: analysing %s", rel)

        debug_out = _run_readelf(["--debug-dump=str"], path, timeout=_DBG_TIMEOUT)
        if not debug_out:
            continue

        for key, name, ver in _extract_candidates(debug_out):
            known = _match_name_to_known(name)

            # Conservative filter: only known OR versioned
            if known is None and ver is None:
                continue

            if key in found:
                if ver and not found[key].version:
                    found[key].version = ver
                    if found[key].purl and "@" not in found[key].purl:
                        found[key].purl = f"{found[key].purl}@{ver}"
                found[key].matches.append(
                    _dm(rel, None, f"DWARF build/{key}", "build_system")
                )
                continue

            evidence = f"DWARF .debug_str build/{key}"
            if ver:
                evidence += f" ({ver})"
            found[key] = _make_component(name, ver, rel, None, evidence, "build_system")

    if found:
        logger.debug("elf_detector: %d component(s) from %d ELF(s)", len(found), min(len(elf_files), _MAX_ELF))

    return list(found.values())
