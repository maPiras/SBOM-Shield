"""
Pipeline entry point — single function callable from CLI (main.py), the
SSE worker (api/server.py), and the tracking scheduler (core/tracking.py).

The historical inline implementation in `api/server.py` was lifted here
verbatim and made reusable so a periodic re-check from the scheduler shares
the same code path as a user-triggered scan.

Call:

    report = run_pipeline(
        repo_path="/abs/path",
        version="v1.2.3",                       # optional, persisted on the scan row
        context_profile="production_ot",        # str preset, dict, or None
        track_id=None,                          # set by scheduler to link the scan
        options={"extended_coverage": True,
                 "include_indirect": False,
                 "syft_fallback":   True,
                 "online_resolution": False},
        emit=lambda stage, pct, done=False, error=False: ...,
    )

The optional `emit` callback drives the SSE progress stream; pass None to run
silently (used by the scheduler).
"""
from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)

EmitFn = Callable[[str, int], None]


def _noop(stage: str, pct: int, done: bool = False, error: bool = False) -> None:
    pass


def run_pipeline(
    repo_path: str | Path,
    *,
    version: str | None = None,
    context_profile=None,
    track_id: int | None = None,
    options: dict | None = None,
    emit: Optional[Callable] = None,
    output_dir: str | Path | None = None,
) -> dict:
    """Run the full scan + score + prioritise pipeline. Returns the report dict.

    Does NOT persist to the DB or POST to the local API — callers do that so
    they can attach extra metadata (scan_id from the API queue, etc.)."""
    repo_path = str(repo_path)
    emit_fn   = emit or _noop
    opts      = options or {}

    run_ec            = bool(opts.get("extended_coverage", True))
    include_indirect  = bool(opts.get("include_indirect",  False))
    syft_fallback     = bool(opts.get("syft_fallback",     True))
    online_resolution = bool(opts.get("online_resolution", False))

    with tempfile.TemporaryDirectory() as tmp:
        sbom_path = Path(tmp) / "sbom.json"

        # 1 — SBOM
        emit_fn("Generating SBOM with cdxgen...", 15)
        from core.sbom_generator import generate_sbom
        gen = generate_sbom(
            repo_path,
            syft_fallback=syft_fallback,
            online=online_resolution,
        )
        if gen.syft_used and gen.merge_stats:
            emit_fn(
                f"Syft fill-in: +{gen.merge_stats.added_from_secondary} component(s) beyond cdxgen",
                25,
            )
        sbom = gen.sbom
        sbom_path.write_text(json.dumps(sbom, indent=2))

        sbom_meta: dict = {
            "cdxgen_used":       gen.cdxgen_used,
            "syft_used":         gen.syft_used,
            "online_resolution": online_resolution,
        }
        if gen.merge_stats:
            sbom_meta["merge"] = {
                "cdxgen_components":  gen.merge_stats.primary_count,
                "syft_components":    gen.merge_stats.secondary_count,
                "added_from_syft":    gen.merge_stats.added_from_secondary,
                "duplicates_skipped": gen.merge_stats.duplicates_skipped,
            }

        # 2 — Parse
        emit_fn("Parsing CycloneDX components...", 30)
        from core.sbom_parser import parse_sbom
        components = parse_sbom(sbom)

        # 3a — Manifest constraint enrichment
        emit_fn("Parsing manifest constraints...", 38)
        from core.requirements_parser import enrich_components as manifest_enrich
        components, n_manifest = manifest_enrich(components, Path(repo_path))
        if n_manifest:
            emit_fn(f"Manifest parser: {n_manifest} constrained dep(s) added...", 42)

        # 3b — Conan custom manifests
        from core.extended_coverage.conan_parser import enrich_components as conan_enrich
        components, n_conan = conan_enrich(components, Path(repo_path))
        if n_conan:
            emit_fn(f"Conan parser: {n_conan} component(s) added...", 44)

        # 4 — extended_coverage
        if run_ec:
            emit_fn("OT/ICS layer analysis...", 45)
            from core.extended_coverage import run as ec_run, enrich as ec_enrich
            ec_result  = ec_run(repo_path)
            enrich_res = ec_enrich(components, ec_result)
            if enrich_res.added:
                emit_fn(
                    f"extended_coverage: {len(enrich_res.added)} implicit component(s) added...",
                    55,
                )
            scan_components = enrich_res.components
        else:
            from core.extended_coverage.models import OTScanResult, EnrichmentResult
            ec_result  = OTScanResult(target=repo_path)
            enrich_res = EnrichmentResult(
                components=components, added=[],
                skipped_no_purl=0, skipped_duplicate=0, skipped_low_confidence=0,
            )
            scan_components = components

        # 4b — Reachability tagging
        from core import noise_filter as _reach
        all_components = list(scan_components)
        n_indirect = _reach.tag(all_components, repo_path)
        if n_indirect and not include_indirect:
            scan_components = [c for c in all_components if c.directly_used]
            emit_fn(f"Reachability: {n_indirect} indirect component(s) excluded…", 60)

        # 5 — Vuln scan
        emit_fn("Querying OSV + NVD + KEV...", 65)
        from core.vuln_checker import scan as vuln_scan
        results = vuln_scan(scan_components)

        # 6 — Report
        emit_fn("Applying vulnerability scoring...", 82)
        from core.report_generator import build_report
        report = build_report(results, repo_path)
        report["extended_coverage"] = ec_result.to_dict()
        report["extended_coverage"]["enabled"] = run_ec
        report["extended_coverage"]["enrichment"] = {
            "added":                  len(enrich_res.added),
            "skipped_duplicate":      enrich_res.skipped_duplicate,
            "skipped_no_purl":        enrich_res.skipped_no_purl,
            "skipped_low_confidence": enrich_res.skipped_low_confidence,
            "injected_components": [
                {"name": c.name, "version": c.version, "purl": c.purl}
                for c in enrich_res.added
            ],
        }
        report["detected"] = [
            {
                "name":       ot.name,
                "category":   ot.category,
                "confidence": ot.confidence,
                "reason":     "no_purl",
                "matches":    [m.to_dict() for m in ot.matches[:3]],
            }
            for ot in enrich_res.unanalyzed
        ]
        report["sbom_generation"] = sbom_meta
        report["sbom_components"] = [
            {
                "name":              c.name,
                "version":           c.version or "",
                "purl":              c.purl or "",
                "ecosystem":         c.ecosystem or "",
                "source":            getattr(c, "source", None) or "unknown",
                "extended_injected": getattr(c, "extended_injected", False),
                "directly_used":     getattr(c, "directly_used", True),
            }
            for c in all_components
        ]
        report["indirect_components"] = [
            {"name": c.name, "version": c.version or "", "purl": c.purl or ""}
            for c in all_components
            if not getattr(c, "directly_used", True)
        ]

        # 7 — Prioritisation (SSVC bucket + intra-bucket score)
        emit_fn("Computing SSVC priority...", 90)
        from core.priority import prioritize
        prioritize(report, context_profile)

        # Stamp metadata used by the persistence layer
        if version is not None:
            report["version"] = version
        if track_id is not None:
            report["track_id"] = track_id

        # Optional disk artefact
        if output_dir:
            from core.report_generator import save_report
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            save_report(report, out / "security_report.json")

        emit_fn("Pipeline complete.", 100)
        return report
