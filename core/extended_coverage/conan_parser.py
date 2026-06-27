"""
Conan package parser for SBOM-Shield.

Handles non-standard Conan build files that Syft cannot parse:
  - conan.lock.*  : lock files with pinned versions (authoritative)
  - conan_*.txt   : custom requirement files with version ranges (fallback)

Lock files take precedence over requirement files for the same package.
The lower bound of a version range is used when no lock entry is available.
"""
import json
import logging
import re
from pathlib import Path

from core.sbom_parser import Component

logger = logging.getLogger(__name__)

# name/version#hash%timestamp  or  name/version
_LOCK_ENTRY_RE = re.compile(r'^([^/]+)/([^#%\s]+)(?:#[^%\s]*)?(?:%[\d.]+)?$')

# Lower bound from Conan version range like ">=3.00.00 <4"
_LOWER_BOUND_RE = re.compile(r'>=?\s*([\w.]+)')


def _parse_lock_entry(entry: str) -> tuple[str, str] | None:
    m = _LOCK_ENTRY_RE.match(entry.strip())
    if not m:
        return None
    return m.group(1).strip(), m.group(2).strip()


def _parse_req_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # name/[>=x.y <z]  — version range, take lower bound
    bracket = re.match(r'^([^/\s]+)/\[([^\]]*)\]', line)
    if bracket:
        name = bracket.group(1).strip()
        lb = _LOWER_BOUND_RE.search(bracket.group(2))
        return name, lb.group(1) if lb else ""

    # name/version  — plain pinned or date-style (e.g. cci.20210521)
    plain = re.match(r'^([^/\s]+)/([^\s\[#]+)', line)
    if plain:
        return plain.group(1).strip(), plain.group(2).strip()

    return None


def _load_lock_file(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning(f"Skipping lock file {path.name}: {exc}")
        return {}

    result: dict[str, str] = {}
    entries = (
        data.get("requires", [])
        + data.get("build_requires", [])
        + data.get("python_requires", [])
    )
    for entry in entries:
        parsed = _parse_lock_entry(entry)
        if parsed:
            result[parsed[0]] = parsed[1]

    logger.debug(f"Lock file {path.name}: {len(result)} package(s)")
    return result


def _load_req_file(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for line in path.read_text().splitlines():
            parsed = _parse_req_line(line)
            if parsed:
                result[parsed[0]] = parsed[1]
    except OSError as exc:
        logger.warning(f"Skipping req file {path.name}: {exc}")

    logger.debug(f"Req file {path.name}: {len(result)} package(s)")
    return result


def _make_component(name: str, version: str) -> Component:
    purl = f"pkg:conan/{name}@{version}" if version else f"pkg:conan/{name}"
    return Component(name=name, version=version, purl=purl, ecosystem="conan",
                     source="conan")


def enrich_components(
    components: list[Component], target_dir: Path
) -> tuple[list[Component], int]:
    """
    Discover Conan dependencies Syft missed and inject them as Components.

    Scans *target_dir* recursively for:
      - conan.lock.*   (pinned, authoritative — override req file versions)
      - conan_*.txt    (version ranges — lower bound used as version)
      - conanfile.txt  (standard Conan manifest, if present)

    Only packages absent from *components* by name are added.
    Returns the extended component list and the count of newly added packages.
    """
    lock_files = sorted(target_dir.rglob("conan.lock*"))
    req_files  = sorted(
        list(target_dir.rglob("conan_*.txt"))
        + list(target_dir.rglob("conanfile.txt"))
    )

    if not lock_files and not req_files:
        return components, 0

    # Req files first (lower priority), then lock files override
    merged: dict[str, str] = {}
    for path in req_files:
        for name, version in _load_req_file(path).items():
            if name not in merged:
                merged[name] = version

    for path in lock_files:
        merged.update(_load_lock_file(path))

    if not merged:
        return components, 0

    existing = {c.name.lower() for c in components}
    new_components: list[Component] = []
    for name, version in merged.items():
        if name.lower() not in existing:
            new_components.append(_make_component(name, version))
            existing.add(name.lower())

    if new_components:
        logger.info(
            f"Conan parser: {len(new_components)} component(s) from "
            f"{len(lock_files)} lock file(s), {len(req_files)} req file(s)"
        )

    return components + new_components, len(new_components)
