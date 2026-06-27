"""
Data models, PURL mapping, and SBOM enrichment for the extended_coverage layer.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Literal, Optional

logger = logging.getLogger(__name__)

# ── Type aliases ──────────────────────────────────────────────────────────────

OTCategory = Literal[
    "FIELDBUS", "PROTOCOL_STACK", "RUNTIME", "RTOS", "BSP_HAL", "SCADA_HMI", "DEVICE_DESC",
    "UNKNOWN",
]
Confidence = Literal["HIGH", "MEDIUM", "LOW"]
DetectionType = Literal["import", "config_file", "build_system", "project_file", "device_desc", "build_manifest", "api_call"]


# ── Core dataclasses ──────────────────────────────────────────────────────────

@dataclass
class DetectionMatch:
    file_path: str
    line_number: Optional[int]
    matched_text: str
    detection_type: DetectionType
    source_type: str = "unknown"   # "vendored" | "remote" | "package_manager" | "unknown"

    def to_dict(self) -> dict:
        return {
            "file": self.file_path, "line": self.line_number,
            "matched": self.matched_text, "detection_type": self.detection_type,
            "source_type": self.source_type,
        }


@dataclass
class OTComponent:
    name: str
    version: Optional[str]
    purl: Optional[str]
    category: OTCategory
    matches: list[DetectionMatch] = field(default_factory=list)
    confidence: Confidence = "MEDIUM"

    @property
    def key(self) -> str:
        return f"{self.category}::{self.name}"

    def to_dict(self) -> dict:
        return {
            "name": self.name, "version": self.version, "purl": self.purl,
            "category": self.category, "confidence": self.confidence,
            # Always surface api_call (verified) evidence; cap other match types at 5
            "matches": [m.to_dict() for m in self.matches
                        if m.detection_type == "api_call"]
                     + [m.to_dict() for m in self.matches
                        if m.detection_type != "api_call"][:5],
        }


@dataclass
class OTScanResult:
    target: str
    components: list[OTComponent] = field(default_factory=list)

    def to_dict(self) -> dict:
        by_cat: dict[str, int] = {}
        for c in self.components:
            by_cat[c.category] = by_cat.get(c.category, 0) + 1
        return {
            "target": self.target,
            "summary": {
                "components_found": len(self.components),
                "by_category":      by_cat,
            },
            "components": [c.to_dict() for c in self.components],
        }


# ── PURL mapping ──────────────────────────────────────────────────────────────

_PURL_MAP: dict[str, tuple[str, str]] = {
    # Fieldbus
    "libmodbus":   ("pkg:github/stephane/libmodbus",        "libmodbus"),
    "pymodbus":    ("pkg:pypi/pymodbus",                    "pymodbus"),
    "modbus-tk":   ("pkg:pypi/modbus-tk",                   "modbus-tk"),
    "jsmodbus":    ("pkg:npm/jsmodbus",                     "jsmodbus"),
    "canopen":     ("pkg:pypi/canopen",                     "canopen"),
    "python-can":  ("pkg:pypi/python-can",                  "python-can"),
    "lely-core":   ("pkg:github/lely-industries/lely-core", "lely-core"),
    "pycomm3":     ("pkg:pypi/pycomm3",                     "pycomm3"),
    "ethernet-ip": ("pkg:npm/ethernet-ip",                  "ethernet-ip"),
    "cpppo":       ("pkg:pypi/cpppo",                       "cpppo"),
    "soem":        ("pkg:github/OpenEtherCATsociety/SOEM",  "SOEM"),
    "snap7":       ("pkg:github/snap7/snap7",              "Snap7"),
    "modbus-serial": ("pkg:npm/modbus-serial",              "modbus-serial"),
    # Protocol stacks
    "open62541":   ("pkg:github/open62541/open62541",       "open62541"),
    "node-opcua":  ("pkg:npm/node-opcua",                   "node-opcua"),
    "opcua":       ("pkg:pypi/opcua",                       "opcua"),
    "asyncua":     ("pkg:pypi/asyncua",                     "asyncua"),
    "pydnp3":      ("pkg:pypi/pydnp3",                      "pydnp3"),
    "opendnp3":    ("pkg:github/automatak/dnp3",            "opendnp3"),
    "bac0":        ("pkg:pypi/BAC0",                        "BAC0"),
    "bacpypes":    ("pkg:pypi/bacpypes",                    "bacpypes"),
    "bacpypes3":   ("pkg:pypi/bacpypes3",                   "bacpypes3"),
    "libiec61850": ("pkg:github/mz-automation/libiec61850", "libiec61850"),
    # MQTT
    "paho-mqtt-py": ("pkg:pypi/paho-mqtt",                   "paho-mqtt"),
    "paho-mqtt-js": ("pkg:npm/mqtt",                         "mqtt.js"),
    "mosquitto":    ("pkg:github/eclipse/mosquitto",         "mosquitto"),
    # Embedded networking
    "lwip":         ("pkg:github/lwip-tcpip/lwip",           "lwIP"),
    "mbedtls":      ("pkg:github/Mbed-TLS/mbedtls",         "mbedTLS"),
    "freertos-tcp": ("pkg:github/FreeRTOS/FreeRTOS-Plus-TCP","FreeRTOS-Plus-TCP"),
    # Embedded crypto / web / compression / IoT libraries (W4 additions)
    "openssl":       ("pkg:github/openssl/openssl",          "OpenSSL"),
    "wolfssl":       ("pkg:github/wolfSSL/wolfssl",          "wolfSSL"),
    "mongoose":      ("pkg:github/cesanta/mongoose",         "Mongoose"),
    "zlib":          ("pkg:github/madler/zlib",              "zlib"),
    "libwebsockets": ("pkg:github/warmcat/libwebsockets",    "libwebsockets"),
    "paho-mqtt-c":   ("pkg:github/eclipse/paho.mqtt.c",      "Paho-MQTT-C"),
    # RTOS / embedded OS
    "freertos":    ("pkg:github/FreeRTOS/FreeRTOS-Kernel",          "FreeRTOS-Kernel"),
    "zephyr":      ("pkg:github/zephyrproject-rtos/zephyr",         "zephyr"),
    "riot":        ("pkg:github/RIOT-OS/RIOT",                      "RIOT"),
    "nuttx":       ("pkg:github/apache/nuttx",                      "nuttx"),
    "mbed-os":     ("pkg:github/ARMmbed/mbed-os",                   "mbed-os"),
    "threadx":     ("pkg:github/azure-rtos/threadx",                "threadx"),
    "contiki":     ("pkg:github/contiki-ng/contiki-ng",             "contiki-ng"),
    # PLC runtimes
    "openplc":          ("pkg:github/thiagoralves/OpenPLC_v3",           "OpenPLC_v3"),
    "matiec":           ("pkg:github/nucleron/matiec",                   "matiec"),
    "iec2c":            ("pkg:github/nucleron/matiec",                   "iec2c"),
    "iecst":            ("pkg:github/nucleron/matiec",                   "iecst"),
    # BSP / HAL
    "esp-idf":     ("pkg:github/espressif/esp-idf",                 "esp-idf"),
    "arduino":     ("pkg:github/arduino/Arduino",                   "Arduino"),
    "platformio":  ("pkg:pypi/platformio",                          "platformio"),
    "nordic-sdk":  ("pkg:github/nrfconnect/sdk-nrf",                "nRF-SDK"),
    "pico-sdk":    ("pkg:github/raspberrypi/pico-sdk",              "pico-sdk"),
}


def purl_for(key: str, version: Optional[str] = None) -> Optional[str]:
    entry = _PURL_MAP.get(key.lower())
    if entry is None:
        kl = key.lower()
        for k, v in _PURL_MAP.items():
            if k in kl:
                entry = v
                break
    if entry is None:
        return None
    base = entry[0]
    return f"{base}@{version}" if version else base


def canonical_name(key: str) -> str:
    entry = _PURL_MAP.get(key.lower())
    return entry[1] if entry else key


# ── SBOM enrichment ───────────────────────────────────────────────────────────

@dataclass
class EnrichmentResult:
    components: list          # list[Component] — merged Syft + OT
    added: list               # list[Component] — only the newly injected
    skipped_no_purl: int
    skipped_duplicate: int
    skipped_low_confidence: int
    unanalyzed: list = field(default_factory=list)   # list[OTComponent] — detected but no PURL
    upgraded: list = field(default_factory=list)     # list[Component] — Syft-found, PURL attached by OT


def _purl_ecosystem(purl: str) -> Optional[str]:
    try:
        return purl.split(":")[1].split("/")[0].lower()
    except (IndexError, AttributeError):
        return None


def enrich(components: list, scan_result: OTScanResult, min_confidence: str = "MEDIUM") -> EnrichmentResult:
    """
    Inject OT-discovered components that Syft missed into *components*
    so they flow through the full vuln_checker pipeline.

    Components with a PURL (including pkg:generic/) are injected.
    pkg:generic/ components won't be queried via OSV but will be routed
    to NVD keyword search in vuln_checker Phase 1c.
    Components with NO PURL at all are skipped (nothing to query).
    Deduplication is by name and PURL (case-insensitive).
    """
    from core.sbom_parser import Component  # local import to avoid circular deps

    accept = {"HIGH"} if min_confidence == "HIGH" else {"HIGH", "MEDIUM"}
    existing_purls = {c.purl.lower() for c in components if c.purl}
    existing_names = {c.name.lower() for c in components}

    added: list[Component] = []
    upgraded: list[Component] = []
    unanalyzed: list[OTComponent] = []
    skip_purl = skip_dup = skip_conf = 0

    for ot in scan_result.components:
        if ot.confidence not in accept:
            skip_conf += 1
            continue
        if not ot.purl or _purl_ecosystem(ot.purl) is None:
            skip_purl += 1
            unanalyzed.append(ot)
            continue
        purl_lc = ot.purl.lower()
        name_lc = ot.name.lower()

        if purl_lc in existing_purls:
            skip_dup += 1
            continue

        if name_lc in existing_names:
            # Syft already found this component — if it has no PURL (e.g. a
            # vendored C library detected as type="file"), attach the OT PURL
            # so the vuln_checker can query it.  Version stays as Syft found it.
            no_purl_match = next(
                (c for c in components if c.name.lower() == name_lc and not c.purl), None
            )
            if no_purl_match is not None:
                no_purl_match.purl      = ot.purl
                no_purl_match.ecosystem = _purl_ecosystem(ot.purl)
                upgraded.append(no_purl_match)
                existing_purls.add(purl_lc)
                logger.info(f"OT enrich: upgraded {no_purl_match.name} with PURL {ot.purl}")
            else:
                skip_dup += 1
            continue

        comp = Component(
            name=ot.name, version=ot.version or "",
            purl=ot.purl, ecosystem=_purl_ecosystem(ot.purl),
            extended_injected=True,
            source="extended_coverage",
        )
        components.append(comp)
        added.append(comp)
        existing_purls.add(purl_lc)
        existing_names.add(name_lc)
        logger.info(f"OT enrich: +{comp.name}@{comp.version or '?'} [{ot.category}/{ot.confidence}]")

    if added or upgraded:
        logger.info(
            f"OT enrichment: {len(added)} added, {len(upgraded)} upgraded, "
            f"{skip_dup} dup, {skip_purl} no-purl, {skip_conf} low-conf"
        )
    return EnrichmentResult(components, added, skip_purl, skip_dup, skip_conf, unanalyzed, upgraded)
