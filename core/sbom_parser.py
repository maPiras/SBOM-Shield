"""
CycloneDX SBOM parser.

Converts a raw CycloneDX JSON dict (as produced by cdxgen, Syft, or the
merge of both) into a flat list of Component dataclass instances.

Only the fields relevant to vulnerability lookup are extracted:
  - name      : package name as reported by the upstream tool
  - version   : pinned version string (empty string if absent)
  - purl      : Package URL — the primary key used by OSV queries
  - ecosystem : normalised ecosystem name derived from the PURL type
  - source    : which tool produced this entry — read from the
                `sbom-shield:source` CycloneDX property if present (set by
                cdxgen_runner / syft_runner). Other producers (manifest
                parser, conan parser, extended_coverage) fill this field
                directly when they construct Component instances.
"""
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Maps the PURL ecosystem prefix (pkg:<type>/…) to the OSV ecosystem name.
# OSV uses its own naming convention that differs slightly from PURL types.
ECOSYSTEM_MAP = {
    "pypi":    "PyPI",
    "npm":     "npm",
    "maven":   "Maven",
    "golang":  "Go",
    "cargo":   "crates.io",
    "gem":     "RubyGems",
    "nuget":   "NuGet",
}

_SOURCE_PROPERTY = "sbom-shield:source"


@dataclass
class Component:
    """A single software component extracted from an SBOM."""
    name: str
    version: str
    purl: str | None = None              # Package URL — used directly in OSV queries
    ecosystem: str | None = None         # Derived from purl type; fallback for OSV
    extended_injected: bool = False      # True when added by extended_coverage enrichment
    directly_used: bool = True           # False when identified as a transitive/indirect dependency
    source: str | None = None            # cdxgen | syft | manifest | conan | extended_coverage

    def __str__(self):
        return f"{self.name}@{self.version} [{self.ecosystem or '?'}]"


def parse_sbom(sbom: dict) -> list[Component]:
    """
    Parse a CycloneDX JSON dict and return one Component per package entry.

    Components with an empty name are silently skipped, as are raw filesystem
    artefacts (`type: "file"`) that Syft sometimes emits without enough
    metadata to query.

    The CycloneDX `metadata.component` (the project being scanned) is also
    skipped if it appears in the components array — cdxgen sometimes lists
    the project itself as a `type: application` entry, and we do not want
    to vuln-scan the user's own code as if it were a third-party dependency.

    Raises
    ------
    ValueError  If *sbom* is not a CycloneDX document.
    """
    if sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("Not a CycloneDX SBOM")

    self_bom_ref = (sbom.get("metadata", {}).get("component") or {}).get("bom-ref")

    components = []
    skipped_files = 0
    for raw in sbom.get("components", []):
        name = raw.get("name", "").strip()
        if not name:
            continue

        if raw.get("type") == "file":
            skipped_files += 1
            continue

        if self_bom_ref and raw.get("bom-ref") == self_bom_ref:
            continue

        purl = raw.get("purl")

        ecosystem = None
        if purl and purl.startswith("pkg:"):
            try:
                ecosystem = purl.split(":")[1].split("/")[0].lower()
            except IndexError:
                pass

        source = None
        for prop in raw.get("properties", []) or []:
            if prop.get("name") == _SOURCE_PROPERTY:
                source = prop.get("value")
                break

        components.append(Component(
            name=name,
            version=raw.get("version", "").strip(),
            purl=purl,
            ecosystem=ecosystem,
            source=source,
        ))

    if skipped_files:
        logger.info(f"Skipped {skipped_files} raw file artefact(s) from SBOM")
    logger.info(f"Parsed {len(components)} components from SBOM")
    return components
