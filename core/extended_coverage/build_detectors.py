"""
Augment-layer build-manifest detectors for sources Syft does not cover.

  detect_autoconf          — configure.ac / configure.in
                             (PKG_CHECK_MODULES, AC_CHECK_LIB)
  detect_esp_idf_manifest  — idf_component.yml (ESP-IDF Component Manager)
  detect_zephyr_manifest   — west.yml / west.yaml (Zephyr West)
  detect_compile_commands  — compile_commands.json (-I / -isystem include paths)
  detect_cmake_link_libs   — CMakeLists.txt target_link_libraries()
                             (usage evidence + detection)

Unknown component names are emitted as pkg:generic/{name}/{name}@{version}
with confidence=LOW so they still reach the vuln checker as named signals.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional

from .models import OTComponent, purl_for
from .scanners import FileIndex, _dm, _comp, _GITMODULE_URL_MAP

logger = logging.getLogger(__name__)

_VER_RX = re.compile(r'v?([\d]+\.[\d]+(?:\.[\d]+(?:\.[\d]+)?)?)')

_VENDOR_DIRS = frozenset({
    "third_party", "vendor", "lib", "external", "deps",
    "libraries", "middlewares", "components", "externals",
    "submodules", "modules",
})


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _norm(name: str) -> str:
    return re.sub(r'[-_\s\.]+', '-', name.strip().lower()).strip('-')


def _ver_from_constraint(s: str) -> Optional[str]:
    m = _VER_RX.search(s)
    return m.group(1) if m else None


def _match_name_to_known(name: str) -> Optional[tuple[str, str]]:
    """
    Try to match a library name to a (component_key, category) pair via the
    shared URL fragment table.  Requires a minimum overlap of 4 characters to
    filter out short noisy names from autoconf / compile_commands output.
    """
    nl = _norm(name).replace('-', '')
    if len(nl) < 2:
        return None
    best: Optional[tuple[str, str]] = None
    best_len = 0
    for fragment, key, cat in _GITMODULE_URL_MAP:
        fn = fragment.replace('-', '')
        # Exact (normalised) match wins immediately
        if fn == nl:
            return key, cat
        # Substring match: require meaningful overlap
        min_len = min(len(fn), len(nl))
        if min_len >= 4 and (fn in nl or nl in fn):
            if min_len > best_len:
                best = (key, cat)
                best_len = min_len
    return best


def _make_component(
    name: str,
    version: Optional[str],
    source_file: str,
    lineno: Optional[int],
    evidence: str,
    dtype: str,
) -> OTComponent:
    """
    Build an OTComponent for *name*. Maps to a known PURL when possible;
    falls back to pkg:generic/{name}/{name} with confidence=LOW.
    """
    known = _match_name_to_known(name)
    if known:
        key, cat = known
        dm = _dm(source_file, lineno, evidence, dtype)
        return _comp(key, cat, "HIGH", dm, version)

    n = _norm(name)
    purl = f"pkg:generic/{n}/{n}@{version}" if version else f"pkg:generic/{n}/{n}"
    dm = _dm(source_file, lineno, evidence, dtype)
    return OTComponent(
        name=name, version=version, purl=purl,
        category="UNKNOWN", matches=[dm], confidence="LOW",
    )


# ── detect_autoconf ────────────────────────────────────────────────────────────

# PKG_CHECK_MODULES([VAR], [libname >= version libname2])
_AC_PKG_RX = re.compile(
    r'PKG_CHECK_MODULES\s*\(\s*\[?\w+\]?\s*,\s*\[?([^\])\n]+)',
    re.I,
)
# AC_CHECK_LIB([name], [func], ...)
_AC_LIB_RX = re.compile(r'AC_CHECK_LIB(?:S)?\s*\(\s*\[?([a-zA-Z][^\],\s\)]+)', re.I)
# Single dep entry inside PKG_CHECK_MODULES: name [op version]
_PKG_DEP_RX = re.compile(r'([a-zA-Z][a-zA-Z0-9\-_\.]+)\s*(?:[><=!]+\s*([\d][.\d]*[\d]))?')


def detect_autoconf(idx: FileIndex) -> list[OTComponent]:
    """
    Parse configure.ac / configure.in for external library dependencies.

    Extracts PKG_CHECK_MODULES and AC_CHECK_LIB declarations.
    """
    found: dict[str, OTComponent] = {}
    ac_files = [
        p for p in idx.all_files
        if p.name in ("configure.ac", "configure.in", "configure.ac.in")
    ]
    if not ac_files:
        return []

    for path in ac_files:
        rel  = idx.rel(path)
        text = idx.read(path)
        if not text:
            continue

        for m in _AC_PKG_RX.finditer(text):
            lineno   = text[:m.start()].count('\n') + 1
            deps_str = m.group(1)
            for em in _PKG_DEP_RX.finditer(deps_str):
                lib_name = em.group(1).strip()
                version  = em.group(2)
                # Skip operator-like tokens and pure version strings
                if len(lib_name) < 2 or re.match(r'^\d', lib_name):
                    continue
                if lib_name.lower() in ('and', 'or', 'not', 'required', 'optional'):
                    continue
                evidence = f"PKG_CHECK_MODULES: {lib_name}"
                if version:
                    evidence += f" >= {version}"
                key = _norm(lib_name)
                if key not in found:
                    found[key] = _make_component(
                        lib_name, version, rel, lineno, evidence, "build_manifest"
                    )
                else:
                    found[key].matches.append(_dm(rel, lineno, evidence, "build_manifest"))
                    if version and not found[key].version:
                        found[key].version = version

        for m in _AC_LIB_RX.finditer(text):
            lineno   = text[:m.start()].count('\n') + 1
            lib_name = m.group(1).strip().strip('[]').strip()
            if len(lib_name) < 2:
                continue
            key = _norm(lib_name)
            if key in found:
                continue
            evidence = f"AC_CHECK_LIB: {lib_name}"
            found[key] = _make_component(lib_name, None, rel, lineno, evidence, "build_manifest")

    return list(found.values())


# ── detect_esp_idf_manifest ────────────────────────────────────────────────────

def detect_esp_idf_manifest(idx: FileIndex) -> list[OTComponent]:
    """
    Parse idf_component.yml for ESP-IDF Component Manager dependencies.

    Format::

        dependencies:
          component_name: "^1.0.0"
          namespace/component: ">=2.0"
          git_dep:
            git: https://github.com/...
            version: "1.0.0"
    """
    found: dict[str, OTComponent] = {}
    idf_files = [p for p in idx.all_files if p.name == "idf_component.yml"]
    if not idf_files:
        return []

    for path in idf_files:
        rel  = idx.rel(path)
        text = idx.read(path)
        if not text:
            continue

        try:
            import yaml  # type: ignore[import-untyped]
            data = yaml.safe_load(text) or {}
            deps: dict = data.get("dependencies", {}) or {}
        except Exception:
            deps = _idf_deps_fallback(text)

        for dep_name, dep_val in deps.items():
            if dep_name.lower() == "idf":
                continue
            version: Optional[str] = None
            if isinstance(dep_val, str):
                version = _ver_from_constraint(dep_val)
            elif isinstance(dep_val, dict):
                version = _ver_from_constraint(dep_val.get("version", "") or "")

            # Strip namespace prefix for matching (espressif/esp_mqtt → esp-mqtt)
            short = _norm(dep_name.split("/")[-1])
            evidence = f"idf_component.yml: {dep_name}"
            if version:
                evidence += f"@{version}"

            if short not in found:
                found[short] = _make_component(
                    dep_name.split("/")[-1], version, rel, None, evidence, "build_manifest"
                )
            else:
                found[short].matches.append(_dm(rel, None, evidence, "build_manifest"))
                if version and not found[short].version:
                    found[short].version = version

    return list(found.values())


def _idf_deps_fallback(text: str) -> dict:
    """Regex fallback for idf_component.yml when PyYAML is unavailable."""
    deps: dict = {}
    in_deps = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("dependencies:"):
            in_deps = True
            continue
        if in_deps:
            if s and not line.startswith((' ', '\t')):
                break
            m = re.match(r'\s+([\w/][\w/\-\.]+)\s*:\s*["\']?([^"\'#\n]*)', line)
            if m and m.group(1) not in ("git", "version", "path"):
                deps[m.group(1).strip()] = m.group(2).strip()
    return deps


# ── detect_zephyr_manifest ─────────────────────────────────────────────────────

_GITHUB_RX = re.compile(r'github\.com[/:]([^/\s]+)/([^/\s\.]+)', re.I)


def detect_zephyr_manifest(idx: FileIndex) -> list[OTComponent]:
    """
    Parse west.yml / west.yaml for Zephyr West project dependencies.

    Format::

        manifest:
          projects:
            - name: mbedtls
              url: https://github.com/Mbed-TLS/mbedtls
              revision: v3.4.0
    """
    found: dict[str, OTComponent] = {}
    west_files = [p for p in idx.all_files if p.name in ("west.yml", "west.yaml")]
    if not west_files:
        return []

    for path in west_files:
        rel  = idx.rel(path)
        text = idx.read(path)
        if not text:
            continue

        projects = _parse_west_projects(text)
        for proj in projects:
            name     = (proj.get("name") or "").strip()
            url      = (proj.get("url") or proj.get("remote") or "").strip()
            revision = (proj.get("revision") or proj.get("rev") or "").strip()
            if not name:
                continue

            version  = _ver_from_constraint(revision) if revision else None
            evidence = f"west.yml: {name}"
            if revision:
                evidence += f" rev={revision}"

            key   = _norm(name)
            known = _match_name_to_known(name) or (
                _match_name_to_known(url) if url else None
            )

            if key in found:
                found[key].matches.append(_dm(rel, None, evidence, "build_manifest"))
                if version and not found[key].version:
                    found[key].version = version
                continue

            if known:
                kkey, cat = known
                comp = _comp(kkey, cat, "HIGH", _dm(rel, None, evidence, "build_manifest"), version)
            else:
                gh_m = _GITHUB_RX.search(url) if url else None
                if gh_m:
                    owner, repo = gh_m.group(1), gh_m.group(2)
                    purl = (f"pkg:github/{owner}/{repo}@{revision}"
                            if revision else f"pkg:github/{owner}/{repo}")
                    comp = OTComponent(
                        name=name, version=version, purl=purl,
                        category="UNKNOWN",
                        matches=[_dm(rel, None, evidence, "build_manifest")],
                        confidence="MEDIUM",
                    )
                else:
                    comp = _make_component(name, version, rel, None, evidence, "build_manifest")
            found[key] = comp

    return list(found.values())


def _parse_west_projects(text: str) -> list[dict]:
    try:
        import yaml  # type: ignore[import-untyped]
        data = yaml.safe_load(text) or {}
        return (data.get("manifest", {}) or {}).get("projects", []) or []
    except Exception:
        return _west_projects_fallback(text)


def _west_projects_fallback(text: str) -> list[dict]:
    projects: list[dict] = []
    current: dict = {}
    in_projects = False
    for line in text.splitlines():
        s = line.strip()
        if "projects:" in s:
            in_projects = True
            continue
        if not in_projects:
            continue
        if re.match(r'\s*-\s+name\s*:', line):
            if current.get("name"):
                projects.append(current)
            current = {"name": re.sub(r'.*name\s*:\s*', '', s).strip().strip("'\"")}
        elif current:
            for k in ("url", "revision", "remote", "rev"):
                if f"{k}:" in s:
                    val = s.split(":", 1)[1].strip().strip("'\"")
                    current[k] = val
    if current.get("name"):
        projects.append(current)
    return projects


# ── detect_compile_commands ────────────────────────────────────────────────────

# Matches -I<path>, -I <path>, -isystem <path>
_INC_FLAG_RX = re.compile(r'-I([^\s]+)|-isystem\s+([^\s]+)')


def detect_compile_commands(idx: FileIndex) -> list[OTComponent]:
    """
    Parse compile_commands.json for vendored library include paths.

    Extracts ``-I`` and ``-isystem`` flags pointing into known vendor
    directories (third_party/, vendor/, external/, …) and identifies the
    component from the first sub-directory after the vendor root.

    Catches libraries that are directly vendored in the tree without any
    .gitmodules or CMake FetchContent declaration.
    """
    found: dict[str, OTComponent] = {}
    cc_files = [p for p in idx.all_files if p.name == "compile_commands.json"]
    if not cc_files:
        return []

    root_str = str(idx.root.resolve())

    for path in cc_files:
        rel  = idx.rel(path)
        text = idx.read(path)
        if not text:
            continue
        try:
            entries: list[dict] = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            logger.debug("compile_commands: invalid JSON in %s", rel)
            continue

        # Accumulate (normalised_inc_path → count) across all entries
        inc_counts: dict[str, int] = {}
        for entry in entries:
            cmd       = entry.get("command", "") or " ".join(entry.get("arguments", []))
            directory = entry.get("directory", "")
            for m in _INC_FLAG_RX.finditer(cmd):
                raw = m.group(1) or m.group(2)
                p   = Path(raw) if Path(raw).is_absolute() else Path(directory) / raw
                inc_counts[str(p)] = inc_counts.get(str(p), 0) + 1

        for inc_path_str, count in inc_counts.items():
            parts = Path(inc_path_str).parts
            vendor_idx = next(
                (i for i, part in enumerate(parts) if part.lower() in _VENDOR_DIRS),
                None,
            )
            if vendor_idx is None or vendor_idx + 1 >= len(parts):
                continue
            component_dir = parts[vendor_idx + 1]
            if len(component_dir) < 2:
                continue
            key = _norm(component_dir)
            if key in found:
                continue

            # Make path display relative to project root when possible
            try:
                display = str(Path(inc_path_str).relative_to(root_str))
            except ValueError:
                display = inc_path_str

            evidence = f"compile_commands.json [-I {display}, {count} file(s)]"
            found[key] = _make_component(
                component_dir, None, rel, None, evidence, "build_manifest"
            )

    return list(found.values())


# ── detect_cmake_link_libs ─────────────────────────────────────────────────────

# target_link_libraries(target [PRIVATE|PUBLIC|INTERFACE] lib1 lib2 ...)
_TLL_RX = re.compile(
    r'target_link_libraries\s*\(\s*\S+\s*(?:PRIVATE|PUBLIC|INTERFACE|LINK_PRIVATE|LINK_PUBLIC)?\s*([^)]+)\)',
    re.I | re.S,
)
# Also plain link_libraries(lib1 lib2)
_LL_RX = re.compile(r'(?<!\w)link_libraries\s*\(\s*([^)]+)\)', re.I | re.S)

# Tokens we skip inside link lists
_SKIP_TOKENS = frozenset({
    "private", "public", "interface", "link_private", "link_public",
    "optimized", "debug", "general",
})


def detect_cmake_link_libs(idx: FileIndex) -> list[OTComponent]:
    """
    Parse CMakeLists.txt for target_link_libraries() / link_libraries() calls.

    For each linked library name:
    - If it matches a known fragment → emit HIGH confidence component with
      source_type="linked" (usage evidence, analogous to api_call verification).
    - Otherwise → emit LOW confidence generic component.

    Components already found by detect_build_manifest will be merged by the
    dedup step in detectors.py; the "linked" evidence upgrades confidence.
    """
    found: dict[str, OTComponent] = {}

    for path in idx.all_files:
        if path.name != "CMakeLists.txt":
            continue
        text = idx.read(path)
        if not text:
            continue
        rel = idx.rel(path)

        lib_names: list[tuple[str, int]] = []
        for pattern in (_TLL_RX, _LL_RX):
            for m in pattern.finditer(text):
                lineno  = text[:m.start()].count('\n') + 1
                tokens  = re.split(r'[\s\n\r]+', m.group(1).strip())
                for tok in tokens:
                    tok = tok.strip()
                    if (not tok
                            or tok.startswith('$')        # CMake variable
                            or tok.startswith('-')        # compiler flag
                            or tok.lower() in _SKIP_TOKENS):
                        continue
                    lib_names.append((tok, lineno))

        for lib_name, lineno in lib_names:
            if len(lib_name) < 2:
                continue
            key      = _norm(lib_name)
            evidence = f"target_link_libraries: {lib_name}"
            dm       = _dm(rel, lineno, evidence, "build_manifest", source_type="linked")

            if key in found:
                found[key].matches.append(dm)
                if found[key].confidence == "MEDIUM":
                    found[key].confidence = "HIGH"
            else:
                known = _match_name_to_known(lib_name)
                if known:
                    kkey, cat = known
                    comp = _comp(kkey, cat, "HIGH", dm, None)
                else:
                    # Generic — CMake target names are often custom, keep LOW
                    n    = _norm(lib_name)
                    purl = f"pkg:generic/{n}/{n}"
                    comp = OTComponent(
                        name=lib_name, version=None, purl=purl,
                        category="UNKNOWN", matches=[dm], confidence="LOW",
                    )
                found[key] = comp

    return list(found.values())
