"""
Constraint-based requirements parser.

Syft can only extract components with *pinned* versions (pkg==1.2.3).
This module handles the common case where requirements files use version
constraints (>=, ~=, ^=, <=, !=) by extracting the tightest lower-bound
as a conservative approximation.

Supported manifests
-------------------
Python:  requirements*.txt, constraints*.txt
         pyproject.toml  ([project.dependencies] / [tool.poetry.dependencies])
         setup.cfg       ([options] install_requires)
Node.js: package.json   (dependencies / devDependencies, semver ranges)
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional

from .sbom_parser import Component

logger = logging.getLogger(__name__)

# ─── Version constraint extraction ───────────────────────────────────────────

def _lower_bound(constraint_str: str) -> Optional[str]:
    """
    Return the tightest lower-bound version from a constraint string.

    Examples
    --------
    ">=3.13.3,<3.14"  →  "3.13.3"
    "~=4.25.1"        →  "4.25.1"   (compatible release ≥ 4.25.1)
    "==1.2.3"         →  "1.2.3"
    "^1.2.3"          →  "1.2.3"    (npm caret)
    ">=1.0,!=1.5"     →  "1.0"
    "*"               →  None        (no lower bound)
    """
    # Strip whitespace and extras markers like ;python_version>='3.9'
    s = re.split(r'\s*;', constraint_str)[0].strip()

    # Exact pin  ==1.2.3
    m = re.search(r'==\s*([^\s,]+)', s)
    if m:
        return _clean_ver(m.group(1))

    # Compatible release  ~=4.25.1
    m = re.search(r'~=\s*([^\s,]+)', s)
    if m:
        return _clean_ver(m.group(1))

    # Collect all >= lower bounds
    lowers = re.findall(r'>=\s*([^\s,!<>=]+)', s)
    if lowers:
        # Pick the highest lower bound (most restrictive)
        return _clean_ver(sorted(lowers, key=_ver_tuple, reverse=True)[0])

    # npm / poetry caret  ^1.2.3
    m = re.search(r'\^\s*([^\s,]+)', s)
    if m:
        return _clean_ver(m.group(1))

    # Bare version with no operator
    m = re.fullmatch(r'[~^]?v?([\d]+(?:\.[\d]+)*(?:[-.]?[a-zA-Z0-9]+)*)', s.strip())
    if m:
        return _clean_ver(m.group(1))

    return None


def _clean_ver(v: str) -> str:
    return v.lstrip("v=").strip()


def _ver_tuple(v: str) -> tuple:
    parts = re.split(r'[.\-]', v)
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    return tuple(result)


# ─── Python requirements.txt ─────────────────────────────────────────────────

_PY_LINE = re.compile(
    r'^\s*([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)'   # package name
    r'\s*([><=!~^][^\s#;]*)?'                              # optional constraint
    r'\s*(?:;[^#]*)?'                                      # optional environment marker (;python_version>=...)
    r'\s*(?:#.*)?$'                                        # optional comment
)


def _parse_requirements_txt(path: Path) -> list[tuple[str, Optional[str]]]:
    """Return list of (name, version_or_None) pairs."""
    results = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-r", "-c", "-e", "git+", "http")):
            continue
        m = _PY_LINE.match(line)
        if not m:
            continue
        name       = m.group(1)
        constraint = (m.group(3) or "").strip()
        version    = _lower_bound(constraint) if constraint else None
        results.append((name, version))
    return results


# ─── pyproject.toml ──────────────────────────────────────────────────────────

def _parse_pyproject(path: Path) -> list[tuple[str, Optional[str]]]:
    text = path.read_text(errors="replace")
    results = []

    # [project.dependencies]  PEP 621 style
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r'^\[project\.dependencies\]', stripped):
            in_deps = True; continue
        if re.match(r'^\[', stripped) and in_deps:
            in_deps = False
        if not in_deps:
            continue
        # Each dep is a quoted string:  "aiohttp>=3.x"  or  aiohttp = ">=3.x"
        m = re.search(r'"([^"]+)"', stripped)
        if m:
            dep = m.group(1)
            nm  = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)', dep)
            if nm:
                constraint = dep[nm.end():].strip()
                results.append((nm.group(1), _lower_bound(constraint) if constraint else None))

    # [tool.poetry.dependencies]
    in_poetry = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r'^\[tool\.poetry\.dependencies\]', stripped):
            in_poetry = True; continue
        if re.match(r'^\[', stripped) and in_poetry:
            in_poetry = False
        if not in_poetry:
            continue
        m = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*["\']([^"\']+)["\']', stripped)
        if m:
            results.append((m.group(1), _lower_bound(m.group(2))))

    return results


# ─── setup.cfg ───────────────────────────────────────────────────────────────

def _parse_setup_cfg(path: Path) -> list[tuple[str, Optional[str]]]:
    text = path.read_text(errors="replace")
    results = []
    in_req = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r'install_requires\s*=', stripped):
            in_req = True
            # inline: install_requires = pkg>=1.0
            rest = re.sub(r'install_requires\s*=\s*', '', stripped)
            if rest:
                _add_py_dep(rest, results)
            continue
        if in_req:
            if stripped.startswith("[") or (stripped and not stripped[0].isspace() and "=" in stripped):
                in_req = False
            elif stripped:
                _add_py_dep(stripped, results)
    return results


def _add_py_dep(dep_str: str, results: list):
    m = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)(.*)$', dep_str.strip())
    if m:
        results.append((m.group(1), _lower_bound(m.group(2).strip())))


# ─── package.json (Node.js) ──────────────────────────────────────────────────

def _parse_package_json(path: Path) -> list[tuple[str, Optional[str]]]:
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []
    results = []
    for section in ("dependencies", "optionalDependencies"):
        for name, constraint in (data.get(section) or {}).items():
            results.append((name, _lower_bound(str(constraint))))
    return results


# ─── Orchestrator ─────────────────────────────────────────────────────────────

_MANIFEST_HANDLERS = {
    "requirements.txt":  ("pypi", _parse_requirements_txt),
    "requirements-*.txt":("pypi", _parse_requirements_txt),
    "constraints.txt":   ("pypi", _parse_requirements_txt),
    "pyproject.toml":    ("pypi", _parse_pyproject),
    "setup.cfg":         ("pypi", _parse_setup_cfg),
    "package.json":      ("npm",  _parse_package_json),
}

_SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", ".tox"}


def parse_manifests(root: Path) -> list[tuple[str, Component]]:
    """
    Walk *root*, parse all recognised manifest/requirements files, and
    return (manifest_path_str, Component) pairs.

    Versions are lower-bound approximations for constrained dependencies.
    """
    results: list[tuple[str, Component]] = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        # Skip hidden / venv directories
        if any(part in _SKIP_DIRS or part.startswith(".") for part in path.parts):
            continue

        name = path.name
        for pattern, (ecosystem, handler) in _MANIFEST_HANDLERS.items():
            # Exact name match or glob
            if "*" in pattern:
                prefix, suffix = pattern.split("*", 1)
                matched = name.startswith(prefix) and name.endswith(suffix)
            else:
                matched = name == pattern

            if not matched:
                continue

            try:
                deps = handler(path)
            except Exception as exc:
                logger.debug(f"requirements_parser: skipped {path}: {exc}")
                continue

            rel = str(path.relative_to(root))
            for pkg_name, version in deps:
                if not pkg_name or not version:
                    continue   # no version → would be skipped by vuln_checker anyway
                purl = f"pkg:{ecosystem}/{pkg_name}@{version}"
                results.append((rel, Component(
                    name=pkg_name, version=version, purl=purl, ecosystem=ecosystem,
                    source="manifest",
                )))
            break   # don't apply multiple handlers to same file

    return results


def enrich_components(
    components: list[Component],
    root: Path,
) -> tuple[list[Component], int]:
    """
    Parse manifest files under *root* and inject components that Syft
    missed (typically constrained deps without a pinned version).

    Returns (enriched_list, added_count).
    """
    existing_names = {c.name.lower() for c in components}
    existing_purls = {c.purl.lower() for c in components if c.purl}

    manifest_comps = parse_manifests(root)
    added = 0

    # Deduplicate across manifests too (same pkg in multiple files)
    seen: set[str] = set()

    for manifest_rel, comp in manifest_comps:
        key = comp.name.lower()
        if key in existing_names or key in seen:
            continue
        purl_lc = comp.purl.lower() if comp.purl else None
        if purl_lc and purl_lc in existing_purls:
            continue

        components.append(comp)
        existing_names.add(key)
        seen.add(key)
        if purl_lc:
            existing_purls.add(purl_lc)
        added += 1
        logger.info(f"manifest enrich: +{comp.name}@{comp.version} [{manifest_rel}] (constraint lower-bound)")

    if added:
        logger.info(f"manifest enrichment: {added} component(s) added from constraints")

    return components, added
