"""
core.noise_filter — CVE noise reduction pipeline.

Filters applied after component detection and before vulnerability scanning.
Each strategy lives in its own module.

Active strategies
-----------------
reachability    — marks components as directly_used=False when they are
                  transitive dependencies (lock-file-only) or have no import/
                  include/CMake usage in the project's own source code.
call_verifier   — walks the C/C++ AST (tree-sitter) and checks whether a
                  component's known API symbols are actually called; upgrades
                  OT component confidence MEDIUM→HIGH and appends api_call
                  evidence.  Also used by extended_coverage/detectors.py.

Future strategies (not yet implemented)
----------------------------------------
qt_modules    — Qt sub-module splitting: replace a monolithic qt component
                with per-module entries (qt-network, qt-webengine, …) so
                only actually-imported modules are scanned.
suppress_list — project-level CVE suppression rules (YAML) with expiry dates
                and justification strings, similar to cargo-audit's audit.toml.
"""
from core.noise_filter.reachability import tag
from core.noise_filter.call_verifier import verify_calls

__all__ = ["tag", "verify_calls"]
