"""
Post-detection version enrichment for the extended_coverage layer.

enrich_versions(components, root) -> int

Fills missing version fields on OTComponent objects using four sources
(applied lowest → highest priority so better sources win):

  1. Binary strings  — strings(1) on .elf/.axf binaries (hardcoded patterns)
  2. Hex macros      — #define NAME_VERSION_NUMBER 0xMMmmrr00 in headers
  3. pkg-config .pc  — Version: fields in vendor-tree .pc files
  4. CMakeCache.txt  — <NAME>_VERSION:STRING= entries (highest priority)
"""
from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

_VENDOR_DIRS = frozenset({
    "third_party", "vendor", "lib", "external", "deps",
    "libraries", "middlewares", "components", "externals",
    "submodules", "modules",
})


def _norm(name: str) -> str:
    return re.sub(r'[-_\s\.]+', '-', name.strip().lower()).strip('-')


# ── Source 1: CMakeCache.txt ───────────────────────────────────────────────────

_CACHE_VER_RX = re.compile(
    r'^([A-Za-z][A-Za-z0-9_]+)_VERSION(?:_STRING)?:(?:STRING|STATIC|INTERNAL)\s*=\s*([\d][^\s]*)',
    re.MULTILINE,
)


def _cmake_cache_versions(root: Path) -> dict[str, str]:
    """Scan CMakeCache.txt files for <NAME>_VERSION entries."""
    versions: dict[str, str] = {}
    for cache_file in root.rglob("CMakeCache.txt"):
        try:
            text = cache_file.read_text(errors="replace")
        except OSError:
            continue
        for m in _CACHE_VER_RX.finditer(text):
            key = _norm(m.group(1))
            ver = m.group(2).strip()
            if key and ver:
                versions.setdefault(key, ver)
    return versions


# ── Source 2: pkg-config .pc files ────────────────────────────────────────────

_PC_NAME_RX    = re.compile(r'^Name\s*:\s*(.+)',             re.MULTILINE | re.I)
_PC_VERSION_RX = re.compile(r'^Version\s*:\s*([\d][^\s]*)', re.MULTILINE | re.I)


def _pc_file_versions(root: Path) -> dict[str, str]:
    """Extract Name + Version from .pc files in vendor directories."""
    versions: dict[str, str] = {}
    for pc_file in root.rglob("*.pc"):
        if not any(p.lower() in _VENDOR_DIRS for p in pc_file.parts):
            continue
        try:
            text = pc_file.read_text(errors="replace")
        except OSError:
            continue
        name_m = _PC_NAME_RX.search(text)
        ver_m  = _PC_VERSION_RX.search(text)
        if not (name_m and ver_m):
            continue
        ver = ver_m.group(1).strip()
        for key in (_norm(name_m.group(1)), _norm(pc_file.stem)):
            versions.setdefault(key, ver)
    return versions


# ── Source 3: Hex / split version macros in vendored headers ──────────────────

# Packed: #define MBEDTLS_VERSION_NUMBER 0x03040000
_HEX_VER_RX    = re.compile(r'#\s*define\s+(\w+)_VERSION_NUMBER\s+0x([0-9A-Fa-f]{8})\b')
# Split: #define LWIP_VERSION_MAJOR/MINOR/REVISION n
_SPLIT_MAJ_RX  = re.compile(r'#\s*define\s+(\w+)_VERSION_MAJOR\s+(\d+)')
_SPLIT_MIN_RX  = re.compile(r'#\s*define\s+(\w+)_VERSION_MINOR\s+(\d+)')
_SPLIT_REV_RX  = re.compile(r'#\s*define\s+(\w+)_VERSION_REVISION\s+(\d+)')

_HDR_EXTS = {".h", ".hpp", ".hh", ".h.in"}


def _decode_hex_version(hex_str: str) -> str:
    """0xMMmmrr00 → 'M.m.r'"""
    val   = int(hex_str, 16)
    rev   = (val >> 8)  & 0xFF
    minor = (val >> 16) & 0xFF
    major = (val >> 24) & 0xFF
    return f"{major}.{minor}.{rev}"


def _hex_versions_from_vendored_headers(root: Path) -> dict[str, str]:
    """Scan headers in vendor dirs for packed-hex and split version macros."""
    versions: dict[str, str] = {}
    for path in root.rglob("*"):
        if path.suffix not in _HDR_EXTS:
            continue
        if not any(p.lower() in _VENDOR_DIRS for p in path.parts):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue

        for m in _HEX_VER_RX.finditer(text):
            key = _norm(m.group(1))
            versions.setdefault(key, _decode_hex_version(m.group(2)))

        majors = {m.group(1).lower(): m.group(2) for m in _SPLIT_MAJ_RX.finditer(text)}
        minors = {m.group(1).lower(): m.group(2) for m in _SPLIT_MIN_RX.finditer(text)}
        revs   = {m.group(1).lower(): m.group(2) for m in _SPLIT_REV_RX.finditer(text)}
        for prefix, maj in majors.items():
            key = _norm(prefix)
            ver = f"{maj}.{minors.get(prefix, '0')}.{revs.get(prefix, '0')}"
            versions.setdefault(key, ver)

    return versions


# ── Source 4: Binary embedded strings ─────────────────────────────────────────

_BIN_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("freertos",   re.compile(r'FreeRTOS(?:\s+Kernel)?\s+[Vv]([\d]+\.[\d]+\.[\d]+)', re.I)),
    ("lwip",       re.compile(r'lwIP\s+([\d]+\.[\d]+\.[\d]+)',                        re.I)),
    ("mbedtls",    re.compile(r'mbed\s*TLS\s+([\d]+\.[\d]+\.[\d]+)',                  re.I)),
    ("openssl",    re.compile(r'OpenSSL\s+([\d]+\.[\d]+[\w\.]*)',                     re.I)),
    ("zlib",       re.compile(r'zlib\s+([\d]+\.[\d]+\.[\d]+)',                        re.I)),
    ("sqlite",     re.compile(r'SQLite\s+version\s+([\d]+\.[\d]+\.[\d]+)',             re.I)),
    ("libmodbus",  re.compile(r'libmodbus\s+([\d]+\.[\d]+\.[\d]+)',                    re.I)),
    ("open62541",  re.compile(r'open62541\s+v([\d]+\.[\d]+\.[\d]+)',                   re.I)),
    ("paho-mqtt",  re.compile(r'Paho\s+MQTT\s+([\d]+\.[\d]+\.[\d]+)',                 re.I)),
]

_BIN_EXTS = {".elf", ".axf", ".bin", ".out"}


def _binary_string_versions(root: Path) -> dict[str, str]:
    """Run strings(1) on firmware binaries and match embedded version strings."""
    versions: dict[str, str] = {}
    binaries = [p for p in root.rglob("*") if p.suffix in _BIN_EXTS]
    if not binaries:
        return versions

    try:
        subprocess.run(["strings", "--version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.debug("version_extractor: strings(1) unavailable, skipping binary scan")
        return versions

    for binary in binaries[:20]:
        try:
            proc = subprocess.run(
                ["strings", "-n", "8", str(binary)],
                capture_output=True, text=True, timeout=30,
            )
            output = proc.stdout
        except (OSError, subprocess.TimeoutExpired):
            continue

        for key, pattern in _BIN_PATTERNS:
            if key in versions:
                continue
            m = pattern.search(output)
            if m:
                versions[key] = m.group(1)
                logger.debug(
                    "version_extractor: %s=%s (from %s)", key, m.group(1), binary.name
                )

    return versions


# ── Main enrichment entry point ────────────────────────────────────────────────

def enrich_versions(components: list, root: "Path | str") -> int:
    """
    Fill missing versions on *components* in-place.

    Returns the number of components that received a version.
    """
    root = Path(root).resolve()

    hints: dict[str, str] = {}
    for source_fn in (
        _binary_string_versions,          # lowest priority
        _hex_versions_from_vendored_headers,
        _pc_file_versions,
        _cmake_cache_versions,            # highest priority
    ):
        try:
            for k, v in source_fn(root).items():
                hints[k] = v
        except Exception as exc:          # noqa: BLE001
            logger.debug("version_extractor: %s error: %s", source_fn.__name__, exc)

    if not hints:
        return 0

    enriched = 0
    for comp in components:
        if comp.version:
            continue
        keys: list[str] = [_norm(comp.name)]
        if comp.purl:
            stem = comp.purl.rstrip("/").split("/")[-1].split("@")[0]
            keys.append(_norm(stem))

        for k in keys:
            if k in hints:
                comp.version = hints[k]
                if comp.purl and "@" not in comp.purl:
                    comp.purl = f"{comp.purl}@{comp.version}"
                logger.debug("version_extractor: %s → %s", comp.name, comp.version)
                enriched += 1
                break

    if enriched:
        logger.info(
            "version_extractor: enriched %d component(s) with version data", enriched
        )
    return enriched
