"""
Tree-sitter call-site verifier for C/C++ embedded projects.

Walks call_expression AST nodes in C/C++ source files and checks whether
symbols from detected OT library components are actually called (not just
included via headers).

When a known API symbol is found:
  - A DetectionMatch(detection_type="api_call", source_type="verified")
    is appended to the component as additional evidence.
  - If the component's confidence is MEDIUM it is upgraded to HIGH.

Per-library rules live in `signatures.py` (the shared signature pack also
consumed by `reachability.py`). `_CALL_RULES` is derived from it at import
time so both modules stay in lockstep.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from core.noise_filter.signatures import call_rules

if TYPE_CHECKING:
    from core.extended_coverage.models import OTComponent

logger = logging.getLogger(__name__)

_C_EXTS = frozenset({".c", ".cpp", ".cc", ".cxx"})

# Per-library call rules, derived from signatures.SIGNATURES.
# Each tuple: (fragment, rule)
#   fragment — lowercase string matched against comp.purl + comp.name
#   rule     — dict with optional keys:
#                "prefixes"  : list[str]  — match any call starting with prefix
#                "functions" : list[str]  — match exact call name
# A component is "verified" when at least one call site in the codebase
# matches any prefix or exact name in its rule.
_CALL_RULES: list[tuple[str, dict[str, list[str]]]] = call_rules()


def _load_parser():
    """Lazy-load the tree-sitter C parser; return None if unavailable."""
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_c as tsc
        return Parser(Language(tsc.language()))
    except ImportError:
        return None


def _walk_calls(node, calls: set[str]) -> None:
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is not None:
            calls.add(fn.text.decode("utf-8", errors="replace"))
    for child in node.children:
        _walk_calls(child, calls)


def _collect_calls(root: Path, parser) -> set[str]:
    """Return the set of all function names called in any C/C++ file under root."""
    calls: set[str] = set()
    for path in root.rglob("*"):
        if path.suffix.lower() not in _C_EXTS or not path.is_file():
            continue
        try:
            code = path.read_bytes()
        except OSError:
            continue
        try:
            tree = parser.parse(code)
        except Exception:           # noqa: BLE001
            continue
        _walk_calls(tree.root_node, calls)
    return calls


def _rule_for(comp: "OTComponent") -> dict[str, list[str]] | None:
    """Match a component to a call rule by PURL or name substring (case-insensitive)."""
    target = ((comp.purl or "") + " " + comp.name).lower()
    for fragment, rule in _CALL_RULES:
        if fragment in target:
            return rule
    return None


def verify_calls(components: list["OTComponent"], root: str | Path) -> int:
    """
    Verify that detected components are actually used in C/C++ source.

    Parses every C/C++ file under *root* once, builds a global call-name
    set, then for each component checks whether a known API symbol was
    called.  Returns the count of components that received a verified
    api_call match.
    """
    from core.extended_coverage.models import DetectionMatch

    root = Path(root)
    parser = _load_parser()
    if parser is None:
        logger.warning(
            "call_verifier: tree-sitter not available — skipping call-site verification"
        )
        return 0

    all_calls = _collect_calls(root, parser)
    logger.debug("call_verifier: %d distinct call sites across C/C++ sources", len(all_calls))

    verified = 0
    for comp in components:
        rule = _rule_for(comp)
        if rule is None:
            continue

        matched: list[str] = []
        for fn in all_calls:
            for prefix in rule.get("prefixes", []):
                if fn.startswith(prefix):
                    matched.append(fn)
                    break
            else:
                for exact in rule.get("functions", []):
                    if fn == exact:
                        matched.append(fn)
                        break

        if not matched:
            continue

        sample = ", ".join(sorted(matched)[:4])
        dm = DetectionMatch(
            file_path="<source-tree>",
            line_number=None,
            matched_text=f"api_calls: {sample}",
            detection_type="api_call",     # type: ignore[arg-type]
            source_type="verified",
        )
        comp.matches.append(dm)

        if comp.confidence == "MEDIUM":
            comp.confidence = "HIGH"
            logger.info(
                "call_verifier: %s confidence MEDIUM→HIGH (calls: %s)", comp.name, sample
            )
        else:
            logger.debug("call_verifier: %s already HIGH; api_call evidence appended", comp.name)

        verified += 1

    if verified:
        logger.info("call_verifier: %d component(s) verified via call sites", verified)

    return verified
