"""
Per-library signature pack — single source of truth for both
`reachability.tag()` and `call_verifier.verify_calls()`.

Generalises the historical Qt special case (bespoke `<Q[A-Z]>` / `Qt[56]::`
detection in `reachability.py`) into a table keyed by `_PURL_MAP` key. Each
entry pairs the four kinds of usage signal we already check elsewhere in the
codebase, so reachability and call-verifier can stop duplicating per-library
heuristics:

    includes : regex fragments matched inside `#include <…>` / `#include "…"`
    cmake    : tokens matched (case-insensitive) inside CMake `find_package`
               / `target_link_libraries` blocks
    imports  : regex fragments matched against Python `import X` / `from X`
    calls    : {"prefixes": [...], "functions": [...]} for tree-sitter
               C/C++ AST call-site verification

Components NOT present in this table fall through to reachability's generic
substring / token check (conservative `directly_used=True` default). The table
covers the high-CVE-volume components from the W3 benchmark and the Qt family;
adding more entries is the recommended path to tighten precision further.

Behaviour change introduced together with this file: when a component DOES
have a signature here, signature-miss flips `directly_used = False` (Qt-style
strict mode). This is the whole point of the refactor — replace noisy
substring matching with per-library precision.
"""
from __future__ import annotations

import re
from typing import Optional

_QT_FAMILY_RE = re.compile(r"^qt[0-9a-z]")    # qt5, qtbase, qtwebengine, …

# Signature schema (all fields optional; missing field → no signal of that kind):
#   {
#       "aliases":  [extra-name-patterns],
#       "includes": [regex-fragment, ...],
#       "cmake":    [token, ...],
#       "imports":  [regex-fragment, ...],
#       "calls":    {"prefixes": [...], "functions": [...]},
#   }
#
# Keys are the lowercase _PURL_MAP key. `aliases` lets us map family variants
# (qt5/qt6/qtbase…) to the same signature without duplicating entries.

SIGNATURES: dict[str, dict] = {

    # ─── Qt (historical special case, now generalised) ───────────────────────
    "qt": {
        "aliases":  ["qt5", "qt6", "qtbase", "qt5base", "qt6base"],
        "includes": [r"Q[A-Z]"],         # <QString>, <QObject>, …
        "cmake":    ["Qt5::", "Qt6::"],
        # Qt CVEs are module-level; AST call-site verification would not help.
    },

    # ─── Embedded networking (high-CVE cluster) ──────────────────────────────
    "mbedtls": {
        "includes": [r"mbedtls/"],
        "cmake":    ["mbedtls", "MbedTLS::"],
        "calls":    {"prefixes": ["mbedtls_", "psa_"]},
    },
    "lwip": {
        "includes": [r"lwip/"],
        "cmake":    ["lwip"],
        "calls":    {"functions": [
            "lwip_init", "tcp_new", "tcp_bind", "tcp_listen",
            "tcp_connect", "tcp_write", "tcp_close",
            "udp_new", "udp_bind", "udp_sendto",
            "pbuf_alloc", "pbuf_free", "netif_add",
        ]},
    },
    "freertos-tcp": {
        # Must precede `freertos` in this dict — call_verifier substring match
        # would otherwise route FreeRTOS-Plus-TCP components to the kernel rule.
        "aliases":  ["freertos-plus-tcp"],
        "includes": [r"FreeRTOS_(IP|Sockets|UDP|TCP)"],
        "cmake":    ["freertos-plus-tcp", "freertos_plus_tcp"],
        "calls":    {"prefixes": ["FreeRTOS_"]},
    },

    # ─── RTOS / embedded OS ──────────────────────────────────────────────────
    "freertos": {
        "includes": [r"FreeRTOS\.h", r"FreeRTOSConfig\.h",
                     r"^task\.h", r"^queue\.h", r"^semphr\.h"],
        "cmake":    ["freertos", "freertos_kernel"],
        "calls":    {"functions": [
            "xTaskCreate", "vTaskDelay", "xQueueCreate",
            "xSemaphoreCreateMutex", "vTaskStartScheduler",
        ]},
    },
    "zephyr": {
        "includes": [r"zephyr/"],
        "cmake":    ["zephyr"],
        "calls":    {"prefixes": ["k_"]},
    },
    "threadx": {
        "includes": [r"tx_api\.h", r"tx_port\.h"],
        "cmake":    ["threadx", "azrtos::threadx"],
        "calls":    {"prefixes": ["tx_"]},
    },
    "riot": {
        "includes": [r"riot/", r"riot\.h"],
        "calls":    {"prefixes": ["gnrc_", "xtimer_", "msg_"],
                     "functions": ["thread_create"]},
    },
    "nuttx": {
        # Mostly POSIX; only register the NuttX-specific scheduler extensions
        "includes": [r"nuttx/"],
        "cmake":    ["nuttx"],
        "calls":    {"functions": [
            "task_create", "task_delete",
            "sched_getparam", "sched_setparam",
        ]},
    },
    "mbed-os": {
        "includes": [r"mbed\.h", r"mbed-os/"],
        "cmake":    ["mbed-os", "mbed_os"],
        "calls":    {"prefixes": ["mbed_"]},
    },
    "contiki": {
        "includes": [r"contiki\.h", r"contiki-ng/"],
        "calls":    {"prefixes": ["ctimer_", "etimer_"],
                     "functions": ["process_start", "process_post", "process_exit"]},
    },

    # ─── OT protocol stacks ──────────────────────────────────────────────────
    "open62541": {
        "includes": [r"open62541/", r"open62541\.h"],
        "cmake":    ["open62541"],
        "calls":    {"prefixes": ["UA_"]},
    },
    "libmodbus": {
        "includes": [r"modbus/modbus\.h", r"^modbus\.h"],
        "cmake":    ["modbus", "libmodbus"],
        "calls":    {"prefixes": ["modbus_"]},
    },
    "libiec61850": {
        "includes": [r"libiec61850/", r"iec61850_"],
        "cmake":    ["iec61850", "libiec61850"],
        "calls":    {"prefixes": ["IedServer_", "IedClient_", "MmsServer_"]},
    },
    "mosquitto": {
        "includes": [r"mosquitto\.h"],
        "cmake":    ["mosquitto", "libmosquitto"],
        "calls":    {"prefixes": ["mosquitto_"]},
    },
    "soem": {
        "includes": [r"soem/", r"ethercat\.h"],
        "cmake":    ["soem"],
        "calls":    {"prefixes": ["ec_", "ecx_"]},
    },
    "snap7": {
        "includes": [r"snap7\.h", r"^s7\.h"],
        "cmake":    ["snap7"],
        "calls":    {"prefixes": ["Cli_", "Srv_"]},
    },
    "opendnp3": {
        # C++ — namespaced; call_verifier already handles `opendnp3::` prefix
        "includes": [r"opendnp3/"],
        "cmake":    ["opendnp3"],
        "calls":    {"prefixes": ["opendnp3::"]},
    },
    "lely-core": {
        "includes": [r"lely/"],
        "cmake":    ["lely-core", "lely"],
        "calls":    {"prefixes": ["co_", "can_"]},
    },

    # ─── Embedded crypto / web / compression / IoT libraries (W4 additions) ──
    # High-CVE C libraries routinely vendored into OT/embedded firmware. Each
    # carries a Tier-1 version constant (OPENSSL_VERSION_NUMBER, LWS_LIBRARY_…,
    # ZLIB_VERSION) so detection is version-anchored, and a strict call-prefix so
    # reachability only flips directly_used=True on genuine API use (see
    # notes/signature_pack).
    "openssl": {
        "includes": [r"openssl/"],
        "cmake":    ["openssl", "OpenSSL::SSL", "OpenSSL::Crypto"],
        "calls":    {"prefixes": ["SSL_", "EVP_", "X509_", "BIO_", "RSA_",
                                  "PEM_", "ERR_", "OPENSSL_", "CRYPTO_"]},
    },
    "wolfssl": {
        "includes": [r"wolfssl/"],
        "cmake":    ["wolfssl"],
        "calls":    {"prefixes": ["wolfSSL_", "wc_"]},
    },
    "mongoose": {
        # Cesanta embedded web/network server (not the JS ODM)
        "includes": [r"mongoose\.h"],
        "cmake":    ["mongoose"],
        "calls":    {"prefixes": ["mg_"]},
    },
    "zlib": {
        "includes": [r"zlib\.h", r"zlib/"],
        "cmake":    ["zlib", "ZLIB::ZLIB"],
        "calls":    {"prefixes": ["inflate", "deflate", "gz", "compress",
                                  "uncompress", "crc32", "adler32"]},
    },
    "libwebsockets": {
        "includes": [r"libwebsockets\.h", r"libwebsockets/"],
        "cmake":    ["websockets", "libwebsockets"],
        "calls":    {"prefixes": ["lws_"]},
    },
    "paho-mqtt-c": {
        "includes": [r"MQTTClient\.h", r"MQTTAsync\.h"],
        "cmake":    ["paho", "eclipse-paho-mqtt-c", "paho-mqtt3c", "paho-mqtt3a"],
        "calls":    {"prefixes": ["MQTTClient_", "MQTTAsync_", "MQTTProperties_"]},
    },

    # ─── Python OT/ICS libraries (call_verifier blind — import-only) ─────────
    "asyncua":     {"imports": [r"asyncua"]},
    "opcua":       {"imports": [r"opcua"]},
    "pymodbus":    {"imports": [r"pymodbus"]},
    "python-can":  {"imports": [r"can\.interfaces", r"python_can"]},
    "bac0":        {"imports": [r"BAC0"]},
    "bacpypes":    {"imports": [r"bacpypes"]},
    "bacpypes3":   {"imports": [r"bacpypes3"]},
    "canopen":     {"imports": [r"canopen"]},
    "pycomm3":     {"imports": [r"pycomm3"]},
    "cpppo":       {"imports": [r"cpppo"]},

    # ─── BSP / HAL / vendor SDKs ─────────────────────────────────────────────
    "esp-idf": {
        "includes": [r"esp_[a-z_]+\.h", r"driver/", r"esp_system\.h"],
        "cmake":    ["idf_component_register", "esp-idf", "esp_idf"],
        "calls":    {"prefixes": ["esp_"]},
    },
    "nordic-sdk": {
        "includes": [r"nrfx", r"nrf_[a-z_]+\.h"],
        "cmake":    ["nrfx", "nordic", "nrfconnect"],
        "calls":    {"prefixes": ["nrfx_", "nrf_gpio_", "nrf_uarte_", "nrf_spi_"]},
    },
    "pico-sdk": {
        "includes": [r"pico/stdlib\.h", r"pico/"],
        "cmake":    ["pico_stdlib", "pico_sdk_init"],
        "calls":    {"functions": [
            "stdio_init_all", "sleep_ms", "multicore_launch_core1",
            "watchdog_enable", "flash_range_erase",
            "gpio_init", "gpio_put", "gpio_get",
            "uart_init", "i2c_init", "spi_init", "adc_init",
        ]},
    },
    "arduino": {
        "includes": [r"Arduino\.h"],
        "calls":    {"functions": [
            "digitalWrite", "digitalRead", "analogWrite",
            "analogRead", "pinMode",
        ]},
    },

    # ─── PLC runtimes ────────────────────────────────────────────────────────
    "openplc": {
        # OpenPLC is detected primarily via project files; source signal is sparse
        "includes": [r"openplc"],
        "cmake":    ["openplc"],
    },
}


# ── Resolver ──────────────────────────────────────────────────────────────────

# Reverse-index for aliases — built once at import time.
_ALIAS_INDEX: dict[str, str] = {}
for _key, _sig in SIGNATURES.items():
    for _alias in _sig.get("aliases", []):
        _ALIAS_INDEX[_alias] = _key


def signature_for(name: str) -> Optional[dict]:
    """Return the signature dict for *name* (case-insensitive), or None.

    Resolution order:
      1. Exact lowercase hit in SIGNATURES.
      2. Alias hit (qt5 → qt, qt6base → qt, …).
      3. Family prefix (qt5* → qt, qt6* → qt).
    """
    if not name:
        return None
    nl = name.lower().replace("_", "-")
    if nl in SIGNATURES:
        return SIGNATURES[nl]
    if nl in _ALIAS_INDEX:
        return SIGNATURES[_ALIAS_INDEX[nl]]
    # Qt family — qt5, qt6, qtbase, qtnetwork, qtwebengine, qtsvg, …
    if _QT_FAMILY_RE.match(nl):
        return SIGNATURES.get("qt")
    return None


def call_rules() -> list[tuple[str, dict]]:
    """Return [(fragment, {prefixes/functions})] in the legacy call_verifier
    format. Kept as a function so call_verifier can rebuild on hot reload.

    Aliases are emitted *before* the canonical key so that family variants
    (e.g. `freertos-plus-tcp` → freertos-tcp rule, not the kernel rule)
    win the substring match in `_rule_for`.
    """
    out: list[tuple[str, dict]] = []
    for key, sig in SIGNATURES.items():
        if not sig.get("calls"):
            continue
        for alias in sig.get("aliases", []):
            out.append((alias, sig["calls"]))
        out.append((key, sig["calls"]))
    return out


__all__ = ["SIGNATURES", "signature_for", "call_rules"]
