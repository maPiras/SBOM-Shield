"""
OT component scanners.

Each public function walks the project tree and returns a list of
OTComponent objects for a specific technology domain:

  detect_protocols  — fieldbus libs (Modbus, CANopen, EtherNet/IP ...) and
                      protocol stacks (OPC-UA, DNP3, IEC 61850, BACnet ...)
                      detected via source imports and protocol config files.

  detect_rtos       — RTOS and embedded runtimes (FreeRTOS, Zephyr, RIOT,
                      NuttX, Mbed, ThreadX, ESP-IDF, Arduino, OpenPLC ...)
                      detected via build-system files and config headers.

  detect_bsp        — vendor BSP/HAL layers (STM32 CubeMX, ESP-IDF, TI
                      DriverLib, NXP MCUXpresso, Nordic nRF ...) detected via
                      SDK-specific file names and header includes.

  detect_device_desc — device description files that declare explicit
                      hardware dependencies: EDS (CANopen/DeviceNet), GSDML
                      (PROFINET), ESI (EtherCAT), IODD (IO-Link), FDT/DTM.

All detectors receive a FileIndex (built once by the orchestrator in
detectors.py) so the directory tree is walked exactly once and every file
is read at most once across all detectors.
"""
from __future__ import annotations

import configparser
import logging
import re
import subprocess
from pathlib import Path
from typing import Optional

from .models import OTComponent, DetectionMatch, purl_for, canonical_name

logger = logging.getLogger(__name__)

# ─── Shared constants ─────────────────────────────────────────────────────────

# Skip files larger than this to avoid stalling on generated/minified assets
_MAX_BYTES = 512 * 1024

# Extensions considered "source code" for import/include scans
_SRC_EXTS = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp",   # C / C++
    ".py",                                         # Python
    ".js", ".ts", ".mjs",                          # JavaScript / TypeScript
    ".go",                                         # Go
    ".rs",                                         # Rust
    ".java",                                       # Java
    ".cs",                                         # C#
}

# Directories to skip during the tree walk — build artifacts, caches, VCS
_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn",
    ".venv", "venv", "env", ".env",
    "node_modules",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    "build", "dist", ".cache", ".eggs",
})


# ─── FileIndex ───────────────────────────────────────────────────────────────

class FileIndex:
    """Single-pass file index with content cache.

    Built once per scan by the orchestrator; shared across all detectors
    so the directory tree is walked exactly once and each file is read at
    most once.

    Thread safety: the ``_content`` cache dict is safe for concurrent
    reads/writes under CPython's GIL.  The worst case for a race is a
    harmless duplicate disk read — never corruption.
    """

    def __init__(self, root: Path):
        self.root = root
        self.all_files: list[Path] = []
        self.by_ext: dict[str, list[Path]] = {}
        self._content: dict[Path, str] = {}
        # Names of all .h/.hpp files found in the repo (lower-cased) — used
        # to decide whether a #include target is vendored vs external.
        self.header_names: set[str] = set()
        # Names of all non-hidden, non-skip directories (lower-cased).
        self.dir_names: set[str] = set()
        self._build()

    def _build(self) -> None:
        for path in self.root.rglob("*"):
            if not path.is_file():
                continue
            rel_parts = path.relative_to(self.root).parts
            # Skip files inside junk / hidden directories
            if any(p in _SKIP_DIRS or p.startswith(".") for p in rel_parts[:-1]):
                continue
            try:
                if path.stat().st_size > _MAX_BYTES:
                    continue
            except OSError:
                continue
            self.all_files.append(path)
            ext = path.suffix.lower()
            if ext not in self.by_ext:
                self.by_ext[ext] = []
            self.by_ext[ext].append(path)
            # Populate header/dir sets for vendored-source detection
            if ext in ('.h', '.hpp'):
                self.header_names.add(path.name.lower())
            for part in rel_parts[:-1]:
                if not part.startswith('.') and part not in _SKIP_DIRS:
                    self.dir_names.add(part.lower())

    # ── Content access (cached) ──────────────────────────────────────────

    def read(self, path: Path) -> str:
        """Return text content of *path*, cached.  Works for any path."""
        cached = self._content.get(path)
        if cached is not None:
            return cached
        try:
            size = path.stat().st_size
            text = path.read_text(errors="replace") if size <= _MAX_BYTES else ""
        except OSError:
            text = ""
        self._content[path] = text
        return text

    def lines(self, path: Path) -> list[str]:
        return self.read(path).splitlines()

    # ── Path helpers ─────────────────────────────────────────────────────

    def rel(self, path: Path) -> str:
        """Relative path string from root."""
        return str(path.relative_to(self.root))

    def with_exts(self, *exts: str) -> list[Path]:
        """Return all indexed files whose extension is in *exts*."""
        result: list[Path] = []
        for ext in exts:
            result.extend(self.by_ext.get(ext, []))
        return result


# ─── Shared low-level helpers ─────────────────────────────────────────────────

def _read(path: Path) -> str:
    """Return the text content of *path*, or an empty string on error / oversize.

    Standalone (non-cached) reader for helpers that access files outside
    the index (e.g. submodule directories).
    """
    try:
        return path.read_text(errors="replace") if path.stat().st_size <= _MAX_BYTES else ""
    except OSError:
        return ""


def _lines(path: Path) -> list[str]:
    return _read(path).splitlines()


# Pre-compiled regex to extract the path from a #include directive.
_INCLUDE_HDR_RX = re.compile(r'#\s*include\s+[<"]([^>"]+)[">]')


def _source_type_for_include(idx: FileIndex, line: str) -> str:
    """
    Classify a C/C++ #include line as vendored, or unknown.

    Checks whether the first path component of the included path exists as a
    directory (or the bare header name exists) in the repo tree.  If yes the
    dependency is likely vendored; otherwise we cannot tell without further
    build-system evidence (cross-reference step in detectors.py upgrades
    unknown→remote when a build_manifest match also exists).
    """
    m = _INCLUDE_HDR_RX.search(line)
    if not m:
        return "unknown"
    parts = Path(m.group(1)).parts
    if not parts:
        return "unknown"
    first = parts[0].lower()
    if len(parts) == 1:
        if first in idx.header_names:
            return "vendored"
    else:
        if first in idx.dir_names:
            return "vendored"
    return "unknown"


def _dm(rel: str, lineno: Optional[int], text: str, dtype: str,
        source_type: str = "unknown") -> DetectionMatch:
    """Convenience constructor for DetectionMatch, capped at 120 chars."""
    return DetectionMatch(
        file_path=rel, line_number=lineno,
        matched_text=text[:120],
        detection_type=dtype,          # type: ignore[arg-type]
        source_type=source_type,
    )


def _comp(
    key: str, cat: str, conf: str,
    dm: DetectionMatch, ver: Optional[str] = None,
) -> OTComponent:
    """Build an OTComponent from a component key, resolving its canonical name and PURL."""
    return OTComponent(
        name=canonical_name(key), version=ver, purl=purl_for(key, ver),
        category=cat, matches=[dm], confidence=conf,  # type: ignore[arg-type]
    )


def _extract_version(line: str) -> Optional[str]:
    """
    Best-effort version extraction from a single build-system line.
    Handles patterns like ``revision: v1.2.3``, ``version = "1.2.3"``,
    and ``@1.2.3``.
    """
    m = re.search(
        r'(?:revision|version|tag|ref)\s*[:=]\s*["\']?v?([\d]+\.[\d]+(?:\.[\d]+)?)',
        line, re.I,
    )
    if m:
        return m.group(1)
    m = re.search(r'@v?([\d]+\.[\d]+(?:\.[\d]+)?)', line)
    return m.group(1) if m else None


def _glob_match(name: str, glob: str) -> bool:
    """
    Simple glob matching for file names (``*.h``, ``freertos*.h``, exact names).
    Does not recurse — only the file name is compared, not the full path.
    """
    if "*" not in glob:
        return name.lower() == glob.lower()
    pat = re.escape(glob).replace(r"\*", ".*")
    return bool(re.fullmatch(pat, name, re.I))


# ═══════════════════════════════════════════════════════════════════════════════
# INDUSTRIAL PROTOCOL DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

# Import/include rules: (component_key, category, confidence, [regex_patterns])
_PROTO_IMPORT_RULES: list[tuple[str, str, str, list[str]]] = [
    # Modbus
    ("libmodbus",   "FIELDBUS",       "HIGH",   [r'#\s*include\s+[<"]modbus\.h[">]']),
    ("pymodbus",    "FIELDBUS",       "HIGH",   [r'from\s+pymodbus\b', r'import\s+pymodbus\b']),
    ("modbus-tk",   "FIELDBUS",       "HIGH",   [r'import\s+modbus_tk\b', r'from\s+modbus_tk\b']),
    ("jsmodbus",    "FIELDBUS",       "HIGH",   [r"require\(['\"]jsmodbus['\"]", r"from\s+['\"]jsmodbus['\"]"]),
    # OPC-UA
    ("open62541",   "PROTOCOL_STACK", "HIGH",   [r'#\s*include\s+[<"]open62541/', r'#\s*include\s+[<"]ua_server\.h[">]']),
    ("asyncua",     "PROTOCOL_STACK", "HIGH",   [r'from\s+asyncua\b', r'import\s+asyncua\b']),
    ("opcua",       "PROTOCOL_STACK", "HIGH",   [r'from\s+opcua\b', r'import\s+opcua\b']),
    ("node-opcua",  "PROTOCOL_STACK", "HIGH",   [r"require\(['\"]node-opcua['\"]", r"from\s+['\"]node-opcua['\"]"]),
    # DNP3
    ("pydnp3",      "PROTOCOL_STACK", "HIGH",   [r'from\s+pydnp3\b', r'import\s+pydnp3\b']),
    ("opendnp3",    "PROTOCOL_STACK", "HIGH",   [r'#\s*include\s+[<"]opendnp3/', r'#\s*include\s+[<"]dnp3/']),
    # IEC 61850
    ("libiec61850", "PROTOCOL_STACK", "HIGH",   [r'#\s*include\s+[<"]iec61850', r'#\s*include\s+[<"]mms_value']),
    # BACnet
    ("bacpypes",    "PROTOCOL_STACK", "HIGH",   [r'from\s+bacpypes\b', r'import\s+bacpypes\b']),
    ("bacpypes3",   "PROTOCOL_STACK", "HIGH",   [r'from\s+bacpypes3\b', r'import\s+bacpypes3\b']),
    ("bac0",        "PROTOCOL_STACK", "HIGH",   [r'import\s+BAC0\b', r'from\s+BAC0\b']),
    # CANopen / CAN
    ("canopen",     "FIELDBUS",       "HIGH",   [r'import\s+canopen\b', r'from\s+canopen\b', r'#\s*include\s+[<"]canopen']),
    ("python-can",  "FIELDBUS",       "HIGH",   [r'import\s+can\b', r'from\s+can\b.*Bus']),
    # EtherNet/IP / CIP
    ("pycomm3",     "FIELDBUS",       "HIGH",   [r'from\s+pycomm3\b', r'import\s+pycomm3\b']),
    ("ethernet-ip", "FIELDBUS",       "HIGH",   [r"require\(['\"]ethernet-ip['\"]"]),
    ("cpppo",       "FIELDBUS",       "HIGH",   [r'from\s+cpppo\b', r'import\s+cpppo\b']),
    # EtherCAT
    ("soem",        "FIELDBUS",       "HIGH",   [r'#\s*include\s+[<"]ethercat\.h[">]', r'#\s*include\s+[<"]soem/']),
    # PROFINET / Lely CANopen
    ("lely-core",   "FIELDBUS",       "MEDIUM", [r'#\s*include\s+[<"]lely/can', r'#\s*include\s+[<"]lely/co']),
    # Siemens S7 protocol (Snap7)
    ("snap7",       "PROTOCOL_STACK", "HIGH",   [r'#\s*include\s+[<"]snap7\.h[">]', r'#\s*include\s+[<"]s7_isotcp\.h[">]']),
    # MQTT
    ("paho-mqtt-py","PROTOCOL_STACK", "HIGH",   [r'from\s+paho\b.*mqtt', r'import\s+paho\.mqtt\b']),
    ("paho-mqtt-js","PROTOCOL_STACK", "HIGH",   [r"require\(['\"]mqtt['\"]", r"from\s+['\"]mqtt['\"]"]),
    ("mosquitto",   "PROTOCOL_STACK", "HIGH",   [r'#\s*include\s+[<"]mosquitto\.h[">]']),
    ("paho-mqtt-c", "PROTOCOL_STACK", "HIGH",   [r'#\s*include\s+[<"]MQTTClient\.h[">]', r'#\s*include\s+[<"]MQTTAsync\.h[">]']),
    # Embedded crypto / web / compression / IoT libraries (W4 additions)
    ("openssl",     "PROTOCOL_STACK", "HIGH",   [r'#\s*include\s+[<"]openssl/']),
    ("wolfssl",     "PROTOCOL_STACK", "HIGH",   [r'#\s*include\s+[<"]wolfssl/']),
    ("mongoose",    "PROTOCOL_STACK", "HIGH",   [r'#\s*include\s+[<"]mongoose\.h[">]']),
    ("zlib",        "PROTOCOL_STACK", "HIGH",   [r'#\s*include\s+[<"]zlib\.h[">]', r'#\s*include\s+[<"]zlib/zlib\.h[">]']),
    ("libwebsockets","PROTOCOL_STACK","HIGH",   [r'#\s*include\s+[<"]libwebsockets\.h[">]', r'#\s*include\s+[<"]libwebsockets/']),
    # Embedded networking stacks
    ("lwip",        "PROTOCOL_STACK", "HIGH",   [r'#\s*include\s+[<"]lwip/', r'#\s*include\s+[<"]lwipopts\.h[">]']),
    ("mbedtls",     "PROTOCOL_STACK", "HIGH",   [r'#\s*include\s+[<"]mbedtls/', r'#\s*include\s+[<"]psa/crypto\.h[">]']),
    ("freertos-tcp","PROTOCOL_STACK", "HIGH",   [r'#\s*include\s+[<"]FreeRTOS_IP\.h[">]', r'#\s*include\s+[<"]FreeRTOS_Sockets\.h[">]']),
    # Node.js Modbus
    ("modbus-serial","FIELDBUS",      "HIGH",   [r"require\(['\"]modbus-serial['\"]", r"from\s+['\"]modbus-serial['\"]"]),
]

# Config-file rules: (key, category, confidence, [file_extensions], content_regex_or_None)
_PROTO_CONFIG_RULES: list[tuple[str, str, str, list[str], Optional[str]]] = [
    ("open62541",   "PROTOCOL_STACK", "HIGH",   [".xml"],
     r"<UAEndpoint|opc\.tcp://|OPCUAServer"),
    ("libmodbus",   "FIELDBUS",       "MEDIUM", [".csv", ".json", ".yaml", ".yml", ".ini"],
     r"holding_register|coil_|discrete_input|modbus_address"),
    ("bacpypes",    "PROTOCOL_STACK", "MEDIUM", [".ini", ".cfg"],
     r"\[BACpypes\]|bacnet_bbmd"),
    ("opendnp3",    "PROTOCOL_STACK", "MEDIUM", [".xml", ".json"],
     r"<dnp3|\"dnp3\"|<Outstation|<Master|com\.automatak\.dnp3"),
    # SCL/SSD/SCD/ICD file presence alone implies an IEC 61850 stack dependency
    ("libiec61850", "PROTOCOL_STACK", "HIGH",   [".ssd", ".scd", ".icd", ".cid"], None),
    ("canopen",     "FIELDBUS",       "HIGH",   [".eds"],
     r"\[DeviceInfo\]|\[DummyUsage\]"),
    # ESI file presence implies SOEM or equivalent EtherCAT master
    ("soem",        "FIELDBUS",       "HIGH",   [".esi"], None),
]


def detect_protocols(idx: FileIndex) -> list[OTComponent]:
    """
    Scan for industrial protocol library usage.

    Strategy:
    - Source files  : match import/include patterns line-by-line.
    - Config files  : match file extension + optional content regex.
    Multiple matches for the same library are merged into a single
    OTComponent with all evidence accumulated in .matches.
    """
    found: dict[str, OTComponent] = {}

    # Pre-compile import regexes once
    compiled = [
        (k, c, cf, [re.compile(p, re.I) for p in pats])
        for k, c, cf, pats in _PROTO_IMPORT_RULES
    ]

    # ── Source-file import/include scan ──────────────────────────────────
    for path in idx.with_exts(*_SRC_EXTS):
        rel   = idx.rel(path)
        lines = idx.lines(path)
        for key, cat, conf, rxs in compiled:
            for lineno, line in enumerate(lines, 1):
                for rx in rxs:
                    if rx.search(line):
                        stripped = line.lstrip()
                        if stripped.startswith('#'):
                            src_type = _source_type_for_include(idx, line)
                        else:
                            src_type = "package_manager"
                        dm = _dm(rel, lineno, line.strip(), "import", src_type)
                        if key not in found:
                            found[key] = _comp(key, cat, conf, dm)
                        else:
                            found[key].matches.append(dm)
                        break  # one match per rule per line

    # ── Config-file scan ─────────────────────────────────────────────────
    for key, cat, conf, suffixes, crx_str in _PROTO_CONFIG_RULES:
        crx  = re.compile(crx_str, re.I) if crx_str else None
        for path in idx.with_exts(*suffixes):
            rel = idx.rel(path)
            if crx is None:
                # File presence alone is sufficient evidence
                dm = _dm(rel, None, path.name, "config_file")
            else:
                for lineno, line in enumerate(idx.lines(path), 1):
                    if crx.search(line):
                        dm = _dm(rel, lineno, line.strip(), "config_file")
                        break
                else:
                    continue  # no matching line found
            if key not in found:
                found[key] = _comp(key, cat, conf, dm)
            else:
                found[key].matches.append(dm)

    # ── Filename-based detection for binary artifacts / embedded sources ─
    _FILENAME_RULES: list[tuple[str, str, str, re.Pattern]] = [
        ("snap7", "PROTOCOL_STACK", "HIGH", re.compile(r"snap7", re.I)),
        ("matiec", "RUNTIME",       "HIGH", re.compile(r"\bmatiec\b",          re.I)),
        ("iec2c",  "RUNTIME",       "HIGH", re.compile(r"\biec2c\b",           re.I)),
        ("iecst",  "RUNTIME",       "HIGH", re.compile(r"\biecst\b",           re.I)),
    ]
    for path in idx.all_files:
        name = path.name
        for key, cat, conf, rx in _FILENAME_RULES:
            if rx.search(name):
                rel = idx.rel(path)
                dm  = _dm(rel, None, name, "build_system")
                if key not in found:
                    found[key] = _comp(key, cat, conf, dm)
                else:
                    found[key].matches.append(dm)
                break  # one filename match per file

    # ── Vendored version enrichment ───────────────────────────────────────
    # Components detected only via vendored #includes often lack a version.
    # Walk their matches to find the include prefix, then probe for a
    # version header in the vendored tree.
    for key, comp in found.items():
        if comp.version is not None:
            continue
        for dm in comp.matches:
            if dm.source_type != "vendored":
                continue
            m = _INCLUDE_HDR_RX.search(dm.matched_text)
            if not m:
                continue
            parts = Path(m.group(1)).parts
            if not parts:
                continue
            ver = _version_from_vendored_header(idx.root, parts[0])
            if ver:
                comp.version = ver
                comp.purl = purl_for(key, ver)
                break

    return list(found.values())


# ═══════════════════════════════════════════════════════════════════════════════
# RTOS / RUNTIME DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

# (key, category, confidence, [file_name_globs], [content_patterns])
# Empty content_patterns means file presence alone is sufficient.
_RTOS_RULES: list[tuple[str, str, str, list[str], list[str]]] = [
    # FreeRTOS
    ("freertos",    "RTOS",    "HIGH",   ["FreeRTOSConfig.h", "freertos*.h"], []),
    ("freertos",    "RTOS",    "HIGH",   ["*.c", "*.cpp", "*.h"],
     [r'#\s*include\s+[<"]FreeRTOS\.h[">]', r'\bxTaskCreate\b']),
    ("freertos",    "RTOS",    "MEDIUM", ["CMakeLists.txt"],          [r'FreeRTOS']),
    # Zephyr
    ("zephyr",      "RTOS",    "HIGH",   ["west.yml", "west.yaml"],   [r'zephyrproject-rtos/zephyr']),
    ("zephyr",      "RTOS",    "HIGH",   ["CMakeLists.txt"],          [r'find_package\s*\(\s*Zephyr']),
    ("zephyr",      "RTOS",    "HIGH",   ["prj.conf", "*.conf"],      [r'CONFIG_KERNEL_']),
    ("zephyr",      "RTOS",    "MEDIUM", ["*.c", "*.h"],              [r'#\s*include\s+[<"]zephyr/']),
    # RIOT OS
    ("riot",        "RTOS",    "HIGH",   ["Makefile"],
     [r'^\s*RIOTBASE\s*[:?]?=', r'^\s*USEMODULE\s*\+=']),
    ("riot",        "RTOS",    "HIGH",   ["*.c", "*.h"],              [r'#\s*include\s+[<"]riot/']),
    # NuttX
    ("nuttx",       "RTOS",    "HIGH",   ["defconfig", ".config"],    [r'CONFIG_ARCH_']),
    ("nuttx",       "RTOS",    "HIGH",   ["*.c", "*.h"],              [r'#\s*include\s+[<"]nuttx/config\.h[">]']),
    # Mbed OS
    ("mbed-os",     "RTOS",    "HIGH",   ["mbed_app.json", "mbed-os.lib"], []),
    ("mbed-os",     "RTOS",    "HIGH",   ["*.c", "*.cpp", "*.h"],    [r'#\s*include\s+[<"]mbed\.h[">]']),
    # ThreadX
    ("threadx",     "RTOS",    "HIGH",   ["*.c", "*.h"],              [r'#\s*include\s+[<"]tx_api\.h[">]']),
    # Contiki-NG
    ("contiki",     "RTOS",    "HIGH",   ["Makefile"],                [r'CONTIKI\s*[:?]?=']),
    ("contiki",     "RTOS",    "HIGH",   ["*.c", "*.h"],              [r'#\s*include\s+[<"]contiki\.h[">]']),
    # ESP-IDF
    ("esp-idf",     "RTOS",    "HIGH",   ["sdkconfig", "sdkconfig.defaults"], [r'CONFIG_IDF_TARGET=']),
    ("esp-idf",     "RTOS",    "HIGH",   ["CMakeLists.txt"],          [r'idf_component_register']),
    ("esp-idf",     "RTOS",    "HIGH",   ["idf_component.yml", "idf_component.yaml"], []),
    # Arduino / PlatformIO
    ("platformio",  "RTOS",    "HIGH",   ["platformio.ini"],          [r'\[env:']),
    ("arduino",     "RTOS",    "MEDIUM", ["*.ino", "*.cpp", "*.c"],   [r'#\s*include\s+[<"]Arduino\.h[">]']),
    # Raspberry Pi Pico SDK
    ("pico-sdk",    "RTOS",    "HIGH",   ["CMakeLists.txt"],          [r'pico_sdk_import']),
    ("pico-sdk",    "RTOS",    "HIGH",   ["*.c", "*.h"],              [r'#\s*include\s+[<"]pico/stdlib\.h[">]']),
    # OpenPLC Runtime
    ("openplc",     "RUNTIME", "HIGH",   ["*.cpp", "*.h"],
     [r'#\s*include\s+[<"]ladder\.h[">]', r'OpenPLC_runtime']),
    ("openplc",     "RUNTIME", "HIGH",   ["Makefile", "CMakeLists.txt"], [r'OpenPLC']),
]


def detect_rtos(idx: FileIndex) -> list[OTComponent]:
    """
    Scan for RTOS and embedded runtime indicators.

    Matches file names against the glob list in each rule; when content
    patterns are also specified the file must contain at least one match.
    Versions are extracted opportunistically from the matching line
    (e.g. ``revision: v1.2.3`` in west.yml).
    """
    found: dict[str, OTComponent] = {}
    compiled = [
        (k, c, cf, globs, [re.compile(p, re.I | re.M) for p in pats])
        for k, c, cf, globs, pats in _RTOS_RULES
    ]

    for path in idx.all_files:
        rel  = idx.rel(path)
        name = path.name
        for key, cat, conf, globs, rxs in compiled:
            if not any(_glob_match(name, g) for g in globs):
                continue
            if not rxs:
                # File presence alone
                dm = _dm(rel, None, name, "build_system")
                if key not in found:
                    found[key] = _comp(key, cat, conf, dm)
                else:
                    found[key].matches.append(dm)
                continue
            for lineno, line in enumerate(idx.lines(path), 1):
                for rx in rxs:
                    if rx.search(line):
                        ver = _extract_version(line)
                        dm  = _dm(rel, lineno, line.strip(), "build_system")
                        if key not in found:
                            found[key] = _comp(key, cat, conf, dm, ver)
                        else:
                            if ver and not found[key].version:
                                found[key].version = ver
                                found[key].purl = purl_for(key, ver)
                            found[key].matches.append(dm)
                        break

    return list(found.values())


# ═══════════════════════════════════════════════════════════════════════════════
# BSP / HAL DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

# (key, confidence, [(file_glob, content_rx_or_None, version_rx_or_None)])
_BSP_RULES: list[tuple[str, str, list[tuple[str, Optional[str], Optional[str]]]]] = [
    ("stm32-hal", "HIGH", [
        ("*.ioc",          None,                                         None),
        ("*.h",            r"stm32\w+xx_hal\.h|stm32\w+xx_hal_conf\.h", None),
        ("*.c",            r"HAL_Init\s*\(\s*\)",                        None),
        ("CMakeLists.txt", r"STM32Cube|stm32\w+xx_hal",                  None),
    ]),
    ("esp-idf", "HIGH", [
        # Version can be extracted from sdkconfig's IDF_VER line
        ("sdkconfig", r"IDF_VER=", r'IDF_VER="v?([\d]+\.[\d]+(?:\.[\d]+)?)"'),
    ]),
    ("ti-driverlib", "HIGH", [
        ("*.syscfg", None,                                None),
        ("*.c",      r"#\s*include\s+[<\"]driverlib/",   None),
        ("*.h",      r"#\s*include\s+[<\"]driverlib/",   None),
    ]),
    ("nxp-fsl", "HIGH", [
        ("*.mex", None,                              None),
        ("*.c",   r"#\s*include\s+[<\"]fsl_",        None),
        ("*.h",   r"#\s*include\s+[<\"]fsl_",        None),
    ]),
    ("nordic-sdk", "HIGH", [
        ("west.yml",     r"sdk-nrf|nrfconnect",
         r'revision:\s*v?([\d]+\.[\d]+(?:\.[\d]+)?)'),
        ("*.h",          r"#\s*include\s+[<\"]nrf_", None),
        ("sdk_config.h", None,                        None),
    ]),
    ("pico-sdk", "HIGH", [
        ("CMakeLists.txt", r'pico_sdk_import',
         r'set\s*\(\s*PICO_SDK_VERSION[^"]*"([\d.]+)"'),
    ]),
]


def detect_bsp(idx: FileIndex) -> list[OTComponent]:
    """
    Scan for vendor BSP / HAL layer artifacts.

    A rule matches when the file name matches the glob AND (there is no
    content pattern OR the content pattern is found in the file).
    Version hints are extracted via an optional second regex when present.
    """
    found: dict[str, OTComponent] = {}
    for key, conf, file_rules in _BSP_RULES:
        for file_glob, crx_str, vrx_str in file_rules:
            crx = re.compile(crx_str, re.I) if crx_str else None
            vrx = re.compile(vrx_str, re.I) if vrx_str else None
            for path in idx.all_files:
                if not _glob_match(path.name, file_glob):
                    continue
                rel  = idx.rel(path)
                text = idx.read(path)
                if not text:
                    continue
                if crx and not crx.search(text):
                    continue
                ver = vrx.search(text).group(1) if vrx and vrx.search(text) else None
                # Locate the specific matching line for better diagnostics
                lineno, snippet = None, path.name
                if crx:
                    for i, line in enumerate(text.splitlines(), 1):
                        if crx.search(line):
                            lineno, snippet = i, line.strip()
                            break
                dm = _dm(rel, lineno, snippet, "build_system")
                if key not in found:
                    found[key] = OTComponent(
                        name=canonical_name(key), version=ver,
                        purl=purl_for(key, ver), category="BSP_HAL",
                        matches=[dm], confidence=conf,  # type: ignore[arg-type]
                    )
                else:
                    if ver and not found[key].version:
                        found[key].version = ver
                        found[key].purl = purl_for(key, ver)
                    found[key].matches.append(dm)
    return list(found.values())


# ═══════════════════════════════════════════════════════════════════════════════
# DEVICE DESCRIPTION DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

# Pre-compiled regexes for each device description format
_EDS_RX     = re.compile(r"ProductName\s*=|VendorName\s*=|Baud_10\s*=|Network_ID\s*=", re.I)
_EDS_VER    = re.compile(r"ProductVersion\s*=\s*(.+)",  re.I)
_EDS_NAME   = re.compile(r"ProductName\s*=\s*(.+)",     re.I)
_EDS_VENDOR = re.compile(r"VendorName\s*=\s*(.+)",      re.I)
_EDS_DEVNET = re.compile(r"Network_ID\s*=",             re.I)  # DeviceNet marker
_GSDML_NS   = re.compile(r'xmlns[^=]*=\s*"[^"]*gsdml',  re.I)
_GSD_RX     = re.compile(r'^#Profibus_DP|GSD_Revision\s*=', re.I | re.M)
_ESI_NS     = re.compile(r'xmlns[^=]*=\s*"[^"]*EtherCATInfo', re.I)
_IODD_NS    = re.compile(r'xmlns[^=]*=\s*"[^"]*iodd',   re.I)
_FDCML_NS   = re.compile(r'xmlns[^=]*=\s*"[^"]*FdtCommunication', re.I)

# Extensions that the device description detector examines
_DEV_DESC_EXTS = frozenset({".eds", ".gsd", ".gsdml", ".esi", ".xml"})


def _parse_eds(text: str, path: Path, rel: str) -> Optional[OTComponent]:
    """Parse a CANopen or DeviceNet EDS file and return an OTComponent."""
    if not text or not _EDS_RX.search(text):
        return None
    proto   = "DeviceNet" if _EDS_DEVNET.search(text) else "CANopen"
    name_m  = _EDS_NAME.search(text)
    vendor_m = _EDS_VENDOR.search(text)
    ver_m   = _EDS_VER.search(text)
    product = name_m.group(1).strip()   if name_m   else path.stem
    vendor  = vendor_m.group(1).strip() if vendor_m else "Unknown"
    version = ver_m.group(1).strip()    if ver_m    else None
    purl    = f"pkg:generic/{vendor.lower().replace(' ', '-')}/{product.lower().replace(' ', '-')}"
    if version:
        purl += f"@{version}"
    return OTComponent(
        name=f"{vendor} {product} ({proto})", version=version, purl=purl,
        category="FIELDBUS", confidence="HIGH",  # type: ignore[arg-type]
        matches=[_dm(rel, None, f"{proto} EDS: {product} v{version or '?'} -- {vendor}", "device_desc")],
    )


def _parse_gsdml(text: str, path: Path, rel: str) -> Optional[OTComponent]:
    """Parse a PROFINET GSD or GSDML file."""
    ext  = path.suffix.lower()
    if ext == ".gsdml" or _GSDML_NS.search(text):
        ver_m   = re.search(r'SoftwareRelease="([^"]+)"', text, re.I)
        fam_m   = re.search(r'DeviceFamily="([^"]+)"',    text, re.I)
        version = ver_m.group(1) if ver_m else None
        family  = fam_m.group(1) if fam_m else path.stem
        proto   = "PROFINET GSDML"
    elif ext == ".gsd" and _GSD_RX.search(text):
        version, family, proto = None, path.stem, "Profibus GSD"
    else:
        return None
    return OTComponent(
        name=f"{family} ({proto})", version=version, purl=None,
        category="FIELDBUS", confidence="HIGH",  # type: ignore[arg-type]
        matches=[_dm(rel, None, f"{proto}: {family} v{version or '?'}", "device_desc")],
    )


def _parse_esi(text: str, path: Path, rel: str) -> Optional[OTComponent]:
    """Parse an EtherCAT ESI device description file."""
    if not _ESI_NS.search(text):
        return None
    ver_m  = re.search(r'<Version>([^<]+)</Version>', text, re.I)
    name_m = re.search(r'<Name[^>]*>([^<]+)</Name>',  text, re.I)
    version = ver_m.group(1).strip()  if ver_m  else None
    name    = name_m.group(1).strip() if name_m else path.stem
    return OTComponent(
        name=f"{name} (EtherCAT ESI)", version=version, purl=None,
        category="FIELDBUS", confidence="HIGH",  # type: ignore[arg-type]
        matches=[_dm(rel, None, f"EtherCAT ESI: {name} v{version or '?'}", "device_desc")],
    )


def _parse_iodd(text: str, path: Path, rel: str) -> Optional[OTComponent]:
    """Parse an IO-Link IODD device description file."""
    if not _IODD_NS.search(text):
        return None
    ver_m = re.search(r'releaseVersion="([^"]+)"', text, re.I)
    ven_m = re.search(r'vendorName="([^"]+)"',     text, re.I)
    dev_m = re.search(r'productName="([^"]+)"',    text, re.I)
    version = ver_m.group(1) if ver_m else None
    vendor  = ven_m.group(1) if ven_m else "Unknown"
    device  = dev_m.group(1) if dev_m else path.stem
    return OTComponent(
        name=f"{vendor} {device} (IO-Link)", version=version, purl=None,
        category="FIELDBUS", confidence="HIGH",  # type: ignore[arg-type]
        matches=[_dm(rel, None, f"IO-Link IODD: {vendor} {device} v{version or '?'}", "device_desc")],
    )


def detect_device_desc(idx: FileIndex) -> list[OTComponent]:
    """
    Scan for device description / communication profile files.

    Each file type is dispatched to its own parser.  IODD files are
    identified by the word "iodd" in the file name (they use .xml extension).
    FDT/DTM files are identified by their XML namespace.
    """
    results: list[OTComponent] = []

    for path in idx.with_exts(*_DEV_DESC_EXTS):
        ext = path.suffix.lower()
        rel = idx.rel(path)
        text = idx.read(path)
        comp: Optional[OTComponent] = None

        if ext == ".xml" and re.search(r"iodd", path.name, re.I):
            comp = _parse_iodd(text, path, rel)
        elif ext == ".xml" and _FDCML_NS.search(text):
            comp = OTComponent(
                name=f"{path.stem} (FDT/DTM)", version=None, purl=None,
                category="FIELDBUS", confidence="MEDIUM",  # type: ignore[arg-type]
                matches=[_dm(rel, None, f"FDT/DTM: {path.name}", "device_desc")],
            )
        elif ext == ".eds":
            comp = _parse_eds(text, path, rel)
        elif ext in (".gsd", ".gsdml"):
            comp = _parse_gsdml(text, path, rel)
        elif ext == ".esi":
            comp = _parse_esi(text, path, rel)

        if comp:
            results.append(comp)
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# BUILD MANIFEST DETECTOR (.gitmodules, CMake FetchContent)
# ═══════════════════════════════════════════════════════════════════════════════

# Maps URL path fragments to (component_key, category).
# Checked against the normalised remote URL from .gitmodules.
_GITMODULE_URL_MAP: list[tuple[str, str, str]] = [
    # Fieldbus
    ("libmodbus",                  "libmodbus",    "FIELDBUS"),
    ("modbus",                     "libmodbus",    "FIELDBUS"),
    ("canopen",                    "canopen",      "FIELDBUS"),
    ("lely-core",                  "lely-core",    "FIELDBUS"),
    ("soem",                       "soem",         "FIELDBUS"),
    ("snap7",                      "snap7",        "PROTOCOL_STACK"),
    # Protocol stacks
    ("open62541",                  "open62541",    "PROTOCOL_STACK"),
    ("opendnp3",                   "opendnp3",     "PROTOCOL_STACK"),
    ("dnp3",                       "opendnp3",     "PROTOCOL_STACK"),
    ("libiec61850",                "libiec61850",  "PROTOCOL_STACK"),
    ("mosquitto",                  "mosquitto",    "PROTOCOL_STACK"),
    # Embedded networking
    ("lwip",                       "lwip",         "PROTOCOL_STACK"),
    ("mbedtls",                    "mbedtls",      "PROTOCOL_STACK"),
    ("mbed-tls",                   "mbedtls",      "PROTOCOL_STACK"),
    ("freertos-plus-tcp",          "freertos-tcp", "PROTOCOL_STACK"),
    ("freertos",                   "freertos",     "RTOS"),
    # Embedded crypto / web / compression / IoT libraries (W4 additions)
    ("openssl",                    "openssl",       "PROTOCOL_STACK"),
    ("wolfssl",                    "wolfssl",       "PROTOCOL_STACK"),
    ("mongoose",                   "mongoose",      "PROTOCOL_STACK"),
    ("zlib",                       "zlib",          "PROTOCOL_STACK"),
    ("libwebsockets",              "libwebsockets", "PROTOCOL_STACK"),
    ("paho.mqtt.c",                "paho-mqtt-c",   "PROTOCOL_STACK"),
    # RTOS
    ("zephyr",                     "zephyr",       "RTOS"),
    ("riot",                       "riot",         "RTOS"),
    ("nuttx",                      "nuttx",        "RTOS"),
    ("mbed-os",                    "mbed-os",      "RTOS"),
    ("threadx",                    "threadx",      "RTOS"),
    ("contiki",                    "contiki",      "RTOS"),
    # BSP / HAL
    ("esp-idf",                    "esp-idf",      "RTOS"),
    ("pico-sdk",                   "pico-sdk",     "RTOS"),
    ("sdk-nrf",                    "nordic-sdk",   "RTOS"),
    # PLC runtimes
    ("openplc",                    "openplc",      "RUNTIME"),
    ("matiec",                     "matiec",       "RUNTIME"),
]


def _git_submodule_sha(root: Path, submodule_path: str) -> Optional[str]:
    """Resolve the pinned commit SHA for a submodule via ``git ls-tree``."""
    try:
        result = subprocess.run(
            ["git", "ls-tree", "HEAD", submodule_path],
            capture_output=True, text=True, timeout=10,
            cwd=str(root),
        )
        if result.returncode == 0 and result.stdout.strip():
            # Output: "<mode> commit <sha>\t<path>"
            parts = result.stdout.strip().split()
            if len(parts) >= 3 and len(parts[2]) >= 7:
                return parts[2]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


def _version_from_submodule_files(root: Path, submodule_path: str) -> Optional[str]:
    """
    Attempt version extraction from common version indicator files inside
    a vendored submodule directory.

    Checks (in order):
      - VERSION / version.txt  (plain text version string)
      - version.h / *_version.h  (C #define VERSION "x.y.z")
      - CHANGELOG.md / CHANGES  (first heading with a version number)
      - CMakeLists.txt  (project(... VERSION x.y.z))
    """
    sub_dir = root / submodule_path
    if not sub_dir.is_dir():
        return None

    # Plain-text version files
    for vfile in ("VERSION", "version.txt", "version"):
        vpath = sub_dir / vfile
        if vpath.is_file():
            text = _read(vpath).strip().splitlines()
            if text:
                m = re.search(r'v?([\d]+\.[\d]+(?:\.[\d]+(?:\.[\d]+)?)?)', text[0])
                if m:
                    return m.group(1)

    # C header #define VERSION (recursive — real projects put version.h in subdirs)
    for hfile in sub_dir.rglob("*version*.h"):
        for line in _lines(hfile):
            m = re.search(
                r'#\s*define\s+\w*VERSION\w*\s+"v?([\d]+\.[\d]+(?:\.[\d]+)?)"', line
            )
            if m:
                return m.group(1)

    # CHANGELOG first heading
    for cfile in ("CHANGELOG.md", "CHANGELOG", "CHANGES", "CHANGES.md"):
        cpath = sub_dir / cfile
        if cpath.is_file():
            for line in _lines(cpath)[:30]:
                m = re.search(r'v?([\d]+\.[\d]+(?:\.[\d]+)?)', line)
                if m:
                    return m.group(1)

    # CMakeLists.txt project(... VERSION x.y.z)
    cmake = sub_dir / "CMakeLists.txt"
    if cmake.is_file():
        for line in _lines(cmake)[:50]:
            m = re.search(r'project\s*\([^)]*VERSION\s+([\d]+\.[\d]+(?:\.[\d]+)?)', line, re.I)
            if m:
                return m.group(1)

    return None


def _version_from_vendored_header(root: Path, include_prefix: str) -> Optional[str]:
    """
    Attempt version extraction for a vendored C/C++ library from its in-tree
    version header.

    Searches common vendor directories for a subdirectory whose name starts
    with *include_prefix* (e.g. "mbedtls" from ``#include <mbedtls/ssl.h>``),
    then scans ``*version*.h`` files for:
      1. ``#define *VERSION_STRING* "x.y.z"``  (preferred)
      2. MAJOR + MINOR + MICRO/PATCH triple defines  (fallback)
    """
    _VENDOR_DIRS = ("third_party", "vendor", "lib", "external", "deps",
                    "libraries", "Middlewares", "components")
    prefix_lc = include_prefix.lower()

    for vdir_name in _VENDOR_DIRS:
        vdir = root / vdir_name
        if not vdir.is_dir():
            continue
        for subdir in vdir.iterdir():
            if not subdir.is_dir():
                continue
            if not subdir.name.lower().startswith(prefix_lc):
                continue
            # Pass 1: VERSION_STRING define (most precise)
            for hfile in subdir.rglob("*version*.h"):
                for line in _lines(hfile):
                    m = re.search(
                        r'#\s*define\s+\w*VERSION_STRING\w*\s+"v?([\d]+\.[\d]+(?:\.[\d]+)?)"',
                        line,
                    )
                    if m:
                        return m.group(1)
            # Pass 2: MAJOR / MINOR / MICRO|PATCH triple
            major = minor = patch = None
            for hfile in subdir.rglob("*version*.h"):
                for line in _lines(hfile):
                    if major is None:
                        m = re.search(r'#\s*define\s+\w*VERSION_MAJOR\w*\s+(\d+)', line)
                        if m:
                            major = m.group(1)
                    if minor is None:
                        m = re.search(r'#\s*define\s+\w*VERSION_MINOR\w*\s+(\d+)', line)
                        if m:
                            minor = m.group(1)
                    if patch is None:
                        for suffix in ("_MICRO", "_PATCH"):
                            mp = re.search(
                                r'#\s*define\s+\w*VERSION' + suffix + r'\w*\s+(\d+)', line
                            )
                            if mp:
                                patch = mp.group(1)
                                break
            if major is not None and minor is not None:
                return f"{major}.{minor}" + (f".{patch}" if patch else "")

    return None


def _match_url_to_component(url: str) -> Optional[tuple[str, str]]:
    """Map a git remote URL to (component_key, category) using _GITMODULE_URL_MAP."""
    url_lower = url.lower()
    for fragment, key, cat in _GITMODULE_URL_MAP:
        if fragment in url_lower:
            return key, cat
    return None


def detect_build_manifest(idx: FileIndex) -> list[OTComponent]:
    """
    Scan for build-manifest files that declare vendored dependencies.

    Handles:
      - ``.gitmodules``        -- submodule URL + path, commit SHA, version from
                                  submodule directory files.
      - ``CMakeLists.txt``     -- ``FetchContent_Declare`` and
                                  ``ExternalProject_Add`` blocks: GIT_REPOSITORY
                                  mapped to component, GIT_TAG used as version.

    Each recognised dependency is mapped to an OTComponent with a PURL that
    includes the version (or commit SHA as qualifier) when available.
    """
    found: dict[str, OTComponent] = {}
    root = idx.root

    # ── .gitmodules ──────────────────────────────────────────────────────────
    gitmodules = root / ".gitmodules"
    if gitmodules.is_file():
        cfg = configparser.ConfigParser()
        try:
            cfg.read(str(gitmodules), encoding="utf-8")
        except configparser.Error:
            # Malformed .gitmodules -- try manual fallback
            cfg = configparser.ConfigParser()
            try:
                # .gitmodules can have tabs that ConfigParser dislikes; preprocess
                text = idx.read(gitmodules)
                text = re.sub(r'^\t', '    ', text, flags=re.M)
                cfg.read_string(text)
            except configparser.Error as exc:
                logger.warning(".gitmodules parse error: %s", exc)
                cfg = configparser.ConfigParser()  # empty -- skip gracefully

        for section in cfg.sections():
            url  = cfg.get(section, "url",  fallback="").strip()
            path = cfg.get(section, "path", fallback="").strip()
            if not url:
                continue

            match = _match_url_to_component(url)
            if match is None:
                continue
            key, cat = match

            # Try to resolve version: submodule files first, then commit SHA
            version = _version_from_submodule_files(root, path) if path else None
            sha = _git_submodule_sha(root, path) if path else None

            purl = purl_for(key, version)

            # Build evidence text
            evidence_parts = [f"url={url}"]
            if sha:
                evidence_parts.append(f"sha={sha[:12]}")
            if version:
                evidence_parts.append(f"ver={version}")
            evidence = f".gitmodules [{', '.join(evidence_parts)}]"

            dm = _dm(
                ".gitmodules", None, evidence, "build_manifest",
            )

            if key not in found:
                found[key] = _comp(key, cat, "HIGH", dm, version)
                # Attach SHA as extra evidence even if we got a version
                if sha and not version:
                    # No version -- record SHA in a second match for traceability
                    found[key].matches.append(
                        _dm(path or ".gitmodules", None,
                            f"pinned at commit {sha}", "build_manifest")
                    )
            else:
                found[key].matches.append(dm)
                if version and not found[key].version:
                    found[key].version = version
                    found[key].purl = purl_for(key, version)

    # ── CMake FetchContent_Declare / ExternalProject_Add ─────────────────────
    # Patterns: multi-line blocks like:
    #   FetchContent_Declare(libmodbus
    #     GIT_REPOSITORY https://github.com/stephane/libmodbus.git
    #     GIT_TAG        v3.1.7
    #   )
    _cmake_block_rx = re.compile(
        r'(?:FetchContent_Declare|ExternalProject_Add)\s*\('
        r'(?:[^()]*|\([^()]*\))*\)',
        re.I | re.S,
    )
    _git_repo_rx  = re.compile(r'GIT_REPOSITORY\s+(\S+)', re.I)
    _git_tag_rx   = re.compile(r'GIT_TAG\s+(\S+)',        re.I)
    _ver_from_tag = re.compile(r'v?([\d]+\.[\d]+(?:\.[\d]+(?:\.[\d]+)?)?)')

    for path in idx.all_files:
        if path.name != "CMakeLists.txt":
            continue
        text = idx.read(path)
        if not text:
            continue
        rel = idx.rel(path)

        for block_m in _cmake_block_rx.finditer(text):
            block = block_m.group(0)
            url_m = _git_repo_rx.search(block)
            if not url_m:
                continue
            url = url_m.group(1)
            tag_m   = _git_tag_rx.search(block)
            tag     = tag_m.group(1) if tag_m else None

            comp_match = _match_url_to_component(url)
            if comp_match is None:
                continue
            key, cat = comp_match

            # Extract a semver-ish version from the tag (v3.1.7 → 3.1.7)
            version = None
            if tag:
                vm = _ver_from_tag.search(tag)
                version = vm.group(1) if vm else None

            evidence_parts = [f"url={url}"]
            if tag:
                evidence_parts.append(f"tag={tag}")
            evidence = f"CMake [{', '.join(evidence_parts)}]"

            lineno = text[:block_m.start()].count("\n") + 1
            dm = _dm(rel, lineno, evidence, "build_manifest")

            if key not in found:
                found[key] = _comp(key, cat, "HIGH", dm, version)
            else:
                found[key].matches.append(dm)
                if version and not found[key].version:
                    found[key].version = version
                    found[key].purl = purl_for(key, version)

    return list(found.values())
