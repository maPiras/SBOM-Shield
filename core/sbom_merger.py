"""
CycloneDX SBOM merge — cdxgen primary, syft fill-in.

Strategy: cdxgen wins on conflict. Syft components are added only when they
describe something cdxgen did not already report. A component is considered
"the same" if either of these match against an existing entry:

  - canonical PURL (lowercased; qualifiers and subpath stripped), OR
  - (lowercased name, version) tuple.

The PURL key catches packages where both tools agree on the package URL but
formatted it slightly differently. The (name, version) key catches cases
where one tool emits a PURL and the other does not, or they disagree on the
PURL type (e.g. `pkg:github/` vs `pkg:generic/`) but the component is the
same artefact.

The merged document inherits cdxgen's metadata (specVersion, bom-ref, tools,
etc.) and appends syft-only components to its `components` array. The
`sbom-shield:source` property attached by each runner is preserved untouched.
"""
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class MergeStats:
    primary_count: int          # components from cdxgen
    secondary_count: int        # components from syft (input)
    added_from_secondary: int   # components syft contributed (post-dedup)
    duplicates_skipped: int     # syft components dropped because cdxgen already had them


def merge(primary: dict, secondary: dict) -> tuple[dict, MergeStats]:
    """
    Merge *secondary* into *primary*. Returns (merged_sbom, stats).

    Both inputs must be CycloneDX JSON dicts. The merged dict reuses
    *primary* as its base (specVersion, metadata, serialNumber preserved)
    and appends syft components that cdxgen did not catch.

    The function is non-destructive: it returns a new top-level dict but
    reuses the original component dicts by reference.
    """
    if primary.get("bomFormat") != "CycloneDX" or secondary.get("bomFormat") != "CycloneDX":
        raise ValueError("Both inputs must be CycloneDX SBOMs")

    primary_components = list(primary.get("components", []))
    secondary_components = list(secondary.get("components", []))

    seen_purls: set[str] = set()
    seen_namever: set[tuple[str, str]] = set()
    for comp in primary_components:
        _index(comp, seen_purls, seen_namever)

    added: list[dict] = []
    duplicates = 0
    for comp in secondary_components:
        if _is_duplicate(comp, seen_purls, seen_namever):
            duplicates += 1
            continue
        added.append(comp)
        _index(comp, seen_purls, seen_namever)

    merged = dict(primary)
    merged["components"] = primary_components + added

    stats = MergeStats(
        primary_count=len(primary_components),
        secondary_count=len(secondary_components),
        added_from_secondary=len(added),
        duplicates_skipped=duplicates,
    )
    logger.info(
        f"SBOM merge: cdxgen={stats.primary_count}, syft={stats.secondary_count} "
        f"→ +{stats.added_from_secondary} unique, {stats.duplicates_skipped} duplicate"
    )
    return merged, stats


def _canonical_purl(purl: str | None) -> str | None:
    """Strip qualifiers (`?…`) and subpath (`#…`); lowercase the rest."""
    if not purl:
        return None
    head = purl.split("?", 1)[0].split("#", 1)[0]
    return head.lower()


def _index(comp: dict, purls: set[str], namever: set[tuple[str, str]]) -> None:
    purl = _canonical_purl(comp.get("purl"))
    if purl:
        purls.add(purl)
    name = (comp.get("name") or "").strip().lower()
    if name:
        namever.add((name, (comp.get("version") or "").strip()))


def _is_duplicate(comp: dict, purls: set[str], namever: set[tuple[str, str]]) -> bool:
    purl = _canonical_purl(comp.get("purl"))
    if purl and purl in purls:
        return True
    name = (comp.get("name") or "").strip().lower()
    if name and (name, (comp.get("version") or "").strip()) in namever:
        return True
    return False
