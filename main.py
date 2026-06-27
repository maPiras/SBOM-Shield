#!/usr/bin/env python3
"""
SBOM-Shield — CLI entry point.

Pipeline
--------
1. SBOM generation  : cdxgen produces a CycloneDX JSON from the target
                      directory; Syft is invoked as a secondary scanner and
                      its output is merged in (cdxgen wins on conflict). Use
                      --no-syft-fallback to skip Syft entirely.
2. Parse            : Extract Component objects from the merged SBOM.
3. Manifest enrich  : Inject packages found in requirements.txt / package.json
                      that the SBOM tools missed because they use version
                      constraints (>=x) instead of pinned versions (==x).
4. extended_coverage  : Static analysis for implicit OT/ICS dependencies;
                      results are injected into the component list so they
                      receive full vuln scoring.
5. Vuln scan        : Query OSV, enrich with NVD/KEV, score with EPSS.
6. Report           : Build JSON report, persist to SQLite, print summary.

Exit codes
----------
0  No vulnerabilities at or above --fail-on threshold.
1  At least one vulnerability at or above --fail-on threshold.
2  Fatal error (bad path, SBOM generation failure, parse error).
"""
import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.sbom_generator import generate_sbom, load_sbom
from core.sbom_parser import parse_sbom
from core.vuln_checker import scan, SEVERITY_ORDER
from core.report_generator import build_report, save_report, print_report
from core.extended_coverage import run as ec_run, enrich as ec_enrich
from core.requirements_parser import enrich_components as manifest_enrich
from core.extended_coverage.conan_parser import enrich_components as conan_enrich
from core import noise_filter as reachability
from core.priority import prioritize, DEFAULT_PRESET
from storage.database import init_db, save_scan as db_save_scan

# Internal API endpoint used to forward the report to a running API server.
# Failure here is non-fatal — the report is still written to disk.
_API_SAVE_URL = "http://127.0.0.1:8000/api/internal/scan/save"


def _post_to_api(report: dict, logger) -> None:
    """
    Best-effort POST of the completed report to the local API server.

    Used when the CLI is invoked standalone (outside the API pipeline) so that
    the result still appears in the dashboard.  Any network or server error is
    logged as a warning and execution continues.
    """
    try:
        import urllib.request as _req
        data = json.dumps(report).encode()
        req  = _req.Request(_API_SAVE_URL, data=data,
                            headers={"Content-Type": "application/json"})
        with _req.urlopen(req, timeout=30) as resp:
            logger.info(f"Scan saved to API: {resp.read().decode()[:80]}")
    except Exception as exc:
        logger.warning(f"API save skipped ({exc})")


def _print_ec_summary(ec_result, enrich_res, logger) -> None:
    """
    Log a human-readable summary of the extended_coverage results.

    Logs nothing when no OT components were found — keeps the output clean
    for projects that have no OT/ICS content.
    """
    d = ec_result.to_dict()
    s = d["summary"]
    if s["components_found"] == 0:
        return

    logger.info(
        f"extended_coverage: {s['components_found']} component(s) found "
        f"[{', '.join(f'{k}:{v}' for k, v in s['by_category'].items())}]"
    )

    if enrich_res.added or enrich_res.upgraded:
        logger.info(
            f"OT enrichment: {len(enrich_res.added)} injected, "
            f"{len(enrich_res.upgraded)} upgraded (SBOM-found, PURL attached), "
            f"{enrich_res.skipped_duplicate} duplicate, "
            f"{enrich_res.skipped_no_purl} no-purl skipped"
        )

    if enrich_res.unanalyzed:
        names = ", ".join(c.name for c in enrich_res.unanalyzed[:5])
        extra = f" (+{len(enrich_res.unanalyzed) - 5} more)" if len(enrich_res.unanalyzed) > 5 else ""
        logger.warning(
            f"OT detected (unanalyzable — no PURL): {len(enrich_res.unanalyzed)} "
            f"component(s): {names}{extra}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SBOM-Shield — SBOM-based vulnerability scanner with OT/ICS support"
    )
    parser.add_argument("target_dir",
                        help="Root directory of the project to scan")
    parser.add_argument("--sbom-file", default=None,
                        help="Path to a pre-generated CycloneDX JSON SBOM (skips cdxgen + Syft)")
    parser.add_argument("--no-syft-fallback", dest="syft_fallback",
                        action="store_false", default=True,
                        help="Skip the Syft secondary scan; rely only on cdxgen.")
    parser.add_argument("--online-resolution", dest="online_resolution",
                        action="store_true", default=False,
                        help="Allow cdxgen to perform online dependency resolution "
                             "(default: offline — manifest-only, no registry calls).")
    parser.add_argument("--output-dir", default="./reports",
                        help="Directory for the JSON report and SBOM output")
    parser.add_argument("--fail-on", choices=SEVERITY_ORDER, default="HIGH",
                        help="Minimum severity that causes a non-zero exit code (default: HIGH)")
    parser.add_argument("--extended-coverage", dest="extended_coverage",
                        action=argparse.BooleanOptionalAction, default=True,
                        help="Enable/disable the OT/ICS static-analysis layer "
                             "(default: enabled). Use --no-extended-coverage to skip it.")
    parser.add_argument("--include-indirect", action="store_true", default=False,
                        help="Scan and report CVEs from transitive/indirect dependencies "
                             "(default: those components are skipped to reduce noise).")
    parser.add_argument("--context-profile", default=DEFAULT_PRESET,
                        help=f"Context profile preset name for SSVC prioritisation "
                             f"(default: {DEFAULT_PRESET}). Pass a JSON dict for custom values.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable DEBUG logging")
    args = parser.parse_args()

    # Initialise the SQLite database (creates tables if they don't exist yet)
    init_db()

    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    logger = logging.getLogger("main")

    target_dir = Path(args.target_dir).resolve()
    if not target_dir.exists():
        logger.error(f"Directory not found: {target_dir}")
        return 2

    # ── Step 1: SBOM generation ───────────────────────────────────────────────
    # cdxgen is primary; Syft fills gaps (cdxgen wins on conflict).
    # A pre-generated file shortcuts both tools (useful in CI).
    sbom_meta: dict = {}
    try:
        if args.sbom_file:
            sbom = load_sbom(args.sbom_file)
            sbom_meta = {"source": "pre-generated", "path": args.sbom_file}
        else:
            gen = generate_sbom(
                target_dir,
                syft_fallback=args.syft_fallback,
                online=args.online_resolution,
            )
            sbom = gen.sbom
            sbom_meta = {
                "cdxgen_used": gen.cdxgen_used,
                "syft_used": gen.syft_used,
                "online_resolution": args.online_resolution,
            }
            if gen.merge_stats:
                sbom_meta["merge"] = {
                    "cdxgen_components": gen.merge_stats.primary_count,
                    "syft_components": gen.merge_stats.secondary_count,
                    "added_from_syft": gen.merge_stats.added_from_secondary,
                    "duplicates_skipped": gen.merge_stats.duplicates_skipped,
                }
        sbom_path = Path(args.output_dir) / "sbom.json"
        sbom_path.parent.mkdir(parents=True, exist_ok=True)
        sbom_path.write_text(json.dumps(sbom, indent=2))
    except Exception as e:
        logger.error(f"SBOM failed: {e}")
        return 2

    # ── Step 2: Parse ─────────────────────────────────────────────────────────
    try:
        components = parse_sbom(sbom)
    except ValueError as e:
        logger.error(f"Parse failed: {e}")
        return 2

    # ── Step 3: Manifest constraint enrichment ────────────────────────────────
    # SBOM tools only capture pinned versions reliably.  requirements.txt
    # files using constraints (>=, ~=, ^) are often skipped.  This step parses
    # those manifests and injects the missing components using the lower-bound
    # version.
    components, n_manifest = manifest_enrich(components, target_dir)
    if n_manifest:
        logger.info(f"Manifest parser: {n_manifest} constrained dep(s) added to SBOM")

    # ── Step 3b: Conan enrichment ─────────────────────────────────────────────
    # Neither cdxgen nor Syft recognises the custom Conan file names used by
    # some Intecs projects (conan_*.txt) or the non-standard lock file
    # extensions (.lock.host, .lock.cross).  This step parses those files
    # directly and injects any packages the SBOM tools missed.
    components, n_conan = conan_enrich(components, target_dir)
    if n_conan:
        logger.info(f"Conan parser: {n_conan} component(s) added to SBOM")

    # ── Step 4: extended_coverage static analysis + SBOM enrichment ───────────────────
    # Runs all OT sub-detectors (protocols, RTOS, BSP, PLC/SCADA, device desc)
    # and injects the discovered OT components so they are scanned for
    # vulnerabilities alongside the regular Syft output.  Skipped when the
    # user passes --no-extended-coverage.
    if args.extended_coverage:
        ec_result  = ec_run(target_dir)
        enrich_res = ec_enrich(components, ec_result)
        _print_ec_summary(ec_result, enrich_res, logger)
    else:
        from core.extended_coverage.models import OTScanResult, EnrichmentResult
        logger.info("extended_coverage: disabled via --no-extended-coverage")
        ec_result  = OTScanResult(target=str(target_dir))
        enrich_res = EnrichmentResult(
            components=components, added=[],
            skipped_no_purl=0, skipped_duplicate=0, skipped_low_confidence=0,
            unanalyzed=[],
        )

    # ── Step 4b: Reachability tagging ────────────────────────────────────────
    # Mark components as directly_used=False when they are transitive
    # dependencies (lock-file-only) or have no import/include usage in source.
    n_indirect = reachability.tag(enrich_res.components, target_dir)
    if n_indirect:
        logger.info(
            "reachability: %d indirect component(s) — CVEs suppressed "
            "(use --include-indirect to scan them)", n_indirect
        )

    # ── Step 5: Vulnerability scan ────────────────────────────────────────────
    # Queries OSV for all components, enriches CVE-identified vulns via NVD and
    # the CISA KEV catalogue, then scores with EPSS.
    scan_targets = (enrich_res.components if args.include_indirect
                    else [c for c in enrich_res.components if c.directly_used])
    results = scan(scan_targets)

    # ── Step 6: Report ────────────────────────────────────────────────────────
    report = build_report(results, str(target_dir))

    # Attach extended_coverage results and enrichment metadata to the report so the
    # dashboard and the PDF generator can surface them.
    report["extended_coverage"] = ec_result.to_dict()
    report["extended_coverage"]["enabled"] = args.extended_coverage
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

    # Components detected by extended_coverage but not queryable (no PURL) — surfaced
    # as a "detected" section so users know something was found but unanalyzed.
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
            "name":             c.name,
            "version":          c.version or "",
            "purl":             c.purl or "",
            "ecosystem":        c.ecosystem or "",
            "source":           getattr(c, "source", None) or "unknown",
            "extended_injected": getattr(c, "extended_injected", False),
            "directly_used":    getattr(c, "directly_used", True),
        }
        for c in enrich_res.components
    ]
    report["indirect_components"] = [
        {"name": c.name, "version": c.version or "", "purl": c.purl or ""}
        for c in enrich_res.components
        if not getattr(c, "directly_used", True)
    ]

    # ── Step 6b: Prioritisation (SSVC bucket + intra-bucket score) ───────────
    try:
        profile_arg = args.context_profile
        if profile_arg.strip().startswith("{"):
            profile_arg = json.loads(profile_arg)
        prioritize(report, profile_arg)
        pri_buckets = report.get("priority", {}).get("buckets", {})
        logger.info(
            "priority: Act=%d Attend=%d Track*=%d Track=%d  (profile=%s)",
            pri_buckets.get("Act", 0), pri_buckets.get("Attend", 0),
            pri_buckets.get("Track*", 0), pri_buckets.get("Track", 0),
            report.get("priority", {}).get("profile", {}).get("name", "?"),
        )
    except Exception as exc:
        logger.warning(f"prioritisation skipped: {exc}")

    report_path = Path(args.output_dir) / "security_report.json"
    save_report(report, report_path)
    db_save_scan(report)       # persist to local SQLite for the dashboard
    _post_to_api(report, logger)
    print_report(report)

    # ── Exit code ─────────────────────────────────────────────────────────────
    # Return 1 if any component has a vulnerability at or above --fail-on.
    # This allows CI pipelines to gate on severity.
    threshold = SEVERITY_ORDER.index(args.fail_on)
    for r in results:
        if r.highest_severity and SEVERITY_ORDER.index(r.highest_severity) <= threshold:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
