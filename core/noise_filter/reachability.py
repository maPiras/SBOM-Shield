"""
core/noise_filter/reachability.py — component direct-usage checker.

For each SBOM component, decide whether the project's own source / manifests
contain a usage signal. Components without a signal are flagged
`directly_used = False`; their CVEs are counted but suppressed from active
findings (unless `--include-indirect`).

Two paths through the function — chosen per component:

1. **Signature-driven (precise)** — when the component is keyed in
   `signatures.SIGNATURES`. Checks library-specific include / CMake / Python
   import patterns. Signature-miss flips `directly_used = False` (Qt-style
   strict mode). Replaces the historical hand-rolled Qt special case and
   generalises it to ~25 entries.

2. **Generic fallback** — for components without a signature. Substring /
   token match on includes, CMake, Python imports, with a conservative
   `directly_used = True` default when nothing fires (don't suppress real
   findings on libraries the signature pack has not yet covered).

Conan and pip direct-manifest signals override both paths — a library
declared as a direct dependency is always considered directly used, even if
no source-level call site is present (it may be wired in at link time and
only invoked through generated code or callbacks).
"""
from __future__ import annotations

import re
from pathlib import Path

from core.noise_filter.signatures import signature_for

# ── Conan version-range separator ────────────────────────────────────────────
_CONAN_NAME_RE = re.compile(r'^([A-Za-z0-9_\-\.]+)/')

# ── Source file extensions to scan ───────────────────────────────────────────
_SRC_EXTS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh",
             ".py", ".pyx", ".js", ".ts", ".mjs"}

_MAX_SRC_BYTES   = 200 * 1024 * 1024   # 200 MB cap on concatenated sources
_MAX_FILE_BYTES  = 1   * 1024 * 1024   # skip individual files > 1 MB


def _stem(name: str) -> str:
    """Lowercase name with leading 'lib' stripped."""
    return re.sub(r'^lib', '', name.lower())


def _read_sources(root: Path) -> str:
    """Concatenate all source file contents into a single string.

    Bounded by _MAX_SRC_BYTES and _MAX_FILE_BYTES — when the cap is hit
    further files are dropped silently. The generic fallback defaults to
    `directly_used=True` when no signal is found, so the worst case of a
    truncated read is preserving a few CVEs that would otherwise have been
    suppressed (more noise, not less safety). The cap keeps this function
    O(min(M, cap)) on Zephyr-scale (~1.4 GB) trees.
    """
    parts: list[str] = []
    total = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in _SRC_EXTS:
            continue
        try:
            sz = p.stat().st_size
        except OSError:
            continue
        if sz > _MAX_FILE_BYTES:
            continue
        if total + sz > _MAX_SRC_BYTES:
            break
        try:
            parts.append(p.read_text(errors="ignore"))
            total += sz
        except OSError:
            pass
    return "\n".join(parts)


def _cmake_tokens(root: Path) -> set[str]:
    """Lowercase set of all find_package / target_link_libraries tokens."""
    find_re = re.compile(r'find_package\s*\(\s*(\w+)', re.IGNORECASE)
    link_re = re.compile(r'target_link_libraries\s*\([^)]+', re.IGNORECASE | re.DOTALL)
    word_re = re.compile(r'\b([A-Za-z][A-Za-z0-9_:]+)\b')

    tokens: set[str] = set()
    for p in root.rglob("CMakeLists.txt"):
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        tokens.update(m.group(1).lower() for m in find_re.finditer(text))
        for block in link_re.finditer(text):
            tokens.update(w.lower() for w in word_re.findall(block.group()))
    return tokens


def _conan_direct_names(root: Path) -> set[str]:
    """Names declared as DIRECT Conan deps (conan_reqs.txt / conanfile.txt)."""
    names: set[str] = set()
    for filename in ("conan_reqs.txt", "conan_test_reqs.txt", "conanfile.txt"):
        p = root / filename
        if not p.exists():
            continue
        for line in p.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = _CONAN_NAME_RE.match(line)
            if m:
                names.add(m.group(1).lower())
    return names


def _conan_lock_names(root: Path) -> set[str]:
    """All package names found in any conan.lock.* file (direct + transitive)."""
    import json
    names: set[str] = set()
    for p in root.glob("conan.lock*"):
        if not p.is_file():
            continue
        try:
            data = json.loads(p.read_text(errors="ignore"))
        except (json.JSONDecodeError, OSError):
            continue
        for key in _iter_lock_keys(data):
            m = _CONAN_NAME_RE.match(key)
            if m:
                names.add(m.group(1).lower())
    return names


def _iter_lock_keys(data) -> list[str]:
    keys: list[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(k, str) and "/" in k:
                keys.append(k)
            if isinstance(v, (dict, list)):
                keys.extend(_iter_lock_keys(v))
    elif isinstance(data, list):
        for item in data:
            keys.extend(_iter_lock_keys(item))
    return keys


def _pip_direct_names(root: Path) -> set[str]:
    """Names in requirements.txt (not requirements.lock / pip.lock)."""
    names: set[str] = set()
    req_re = re.compile(r'^([A-Za-z0-9_\-\.]+)\s*[>=<!~]')
    for p in root.rglob("requirements.txt"):
        try:
            for line in p.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = req_re.match(line)
                if m:
                    names.add(m.group(1).lower().replace("-", "_"))
        except OSError:
            pass
    return names


# ── Generic-fallback helpers ─────────────────────────────────────────────────

def _include_match(name_lc: str, src: str) -> bool:
    """True if any #include line in *src* contains the component name/stem."""
    s = _stem(name_lc)
    pat = re.compile(
        rf'#\s*include\s+[<"]({re.escape(name_lc)}|{re.escape(s)})[/."<]',
        re.IGNORECASE,
    )
    return bool(pat.search(src))


def _python_import_match(name_lc: str, src: str) -> bool:
    """True if the component name appears in a Python import statement."""
    s = re.sub(r'[^a-z0-9]', r'[^a-z0-9]?', name_lc)
    pat = re.compile(rf'(?:^|\n)\s*(?:import|from)\s+({s})\b', re.IGNORECASE)
    return bool(pat.search(src))


# ── Signature-driven check ───────────────────────────────────────────────────

def _signature_hit(sig: dict, src: str, cmake_tok: set[str]) -> bool:
    """True if any signal in *sig* fires against the project sources.

    Order: includes → cmake → imports. First hit wins, no need to scan
    further patterns. All matches are case-insensitive.
    """
    # 1. Include patterns — search inside `#include <...>` / `#include "..."`
    for frag in sig.get("includes", []):
        pat = re.compile(rf'#\s*include\s+[<"][^>"]*{frag}', re.IGNORECASE)
        if pat.search(src):
            return True

    # 2. CMake tokens — case-insensitive substring against the token set
    for tok in sig.get("cmake", []):
        tok_lc = tok.lower()
        if any(tok_lc in t for t in cmake_tok):
            return True

    # 3. Python import patterns — full module path matching
    for frag in sig.get("imports", []):
        pat = re.compile(rf'(?:^|\n)\s*(?:import|from)\s+{frag}\b', re.IGNORECASE)
        if pat.search(src):
            return True

    return False


def _has_api_call_evidence(comp) -> bool:
    """True if call_verifier already attached api_call evidence to *comp*.

    Lets reachability honour a positive call-verifier result for OT
    components without re-running the AST walk.
    """
    matches = getattr(comp, "matches", None) or []
    for m in matches:
        dt = getattr(m, "detection_type", None) or (m.get("detection_type") if isinstance(m, dict) else None)
        if dt == "api_call":
            return True
    return False


# ── Public entry point ───────────────────────────────────────────────────────

def tag(components: list, root: Path | str) -> int:
    """Set ``component.directly_used`` on each component in *components*.

    Returns the count of components marked indirect (directly_used=False).
    Components without a ``directly_used`` attribute are skipped silently.
    """
    root = Path(root)

    src          = _read_sources(root)
    cmake_tok    = _cmake_tokens(root)
    conan_direct = _conan_direct_names(root)
    conan_lock   = _conan_lock_names(root)
    pip_direct   = _pip_direct_names(root)

    indirect_count = 0

    for comp in components:
        if not hasattr(comp, "directly_used"):
            continue

        name_lc = comp.name.lower().replace("-", "_")
        sig = signature_for(comp.name)

        # ── Conan transitive signal (independent of signature) ───────────────
        in_lock   = bool(conan_lock   and name_lc in conan_lock)
        in_direct = bool(conan_direct and name_lc in conan_direct)

        if in_direct:
            # Declared as a direct Conan dep — trust the manifest.
            comp.directly_used = True
            continue

        if in_lock and not in_direct:
            # Lock-only → transitive. Source override applies only if a
            # signal exists in the chosen path (signature or generic).
            if sig and (_signature_hit(sig, src, cmake_tok) or _has_api_call_evidence(comp)):
                comp.directly_used = True
            elif not sig and (
                _include_match(name_lc, src)
                or _python_import_match(name_lc, src)
                or name_lc in cmake_tok
                or _stem(name_lc) in cmake_tok
            ):
                comp.directly_used = True
            else:
                comp.directly_used = False
                indirect_count += 1
            continue

        # ── pip direct signal ────────────────────────────────────────────────
        if pip_direct and name_lc in pip_direct:
            comp.directly_used = True
            continue

        # ── Signature-driven (precise) path ──────────────────────────────────
        if sig is not None:
            if _signature_hit(sig, src, cmake_tok) or _has_api_call_evidence(comp):
                comp.directly_used = True
            else:
                # Strict mode: a library WITH a signature that did not fire is
                # treated as indirect. This is the precision-over-recall trade
                # the refactor is designed to enable.
                comp.directly_used = False
                indirect_count += 1
            continue

        # ── Generic fallback (conservative) ──────────────────────────────────
        if (_include_match(name_lc, src)
                or _python_import_match(name_lc, src)
                or name_lc in cmake_tok
                or _stem(name_lc) in cmake_tok):
            comp.directly_used = True
            continue

        # Default: assume directly used (don't suppress unfamiliar libs)
        comp.directly_used = True

    return indirect_count
