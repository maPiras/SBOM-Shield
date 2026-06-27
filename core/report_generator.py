"""
Report builder and renderer.

build_report()  assembles the final security_report.json dict from a list of
ScanResult objects.  The dict is the single source of truth consumed by:
  - save_report()      → security_report.json on disk
  - save_scan()        → SQLite via storage.database
  - PDF generator      → reports/generate_report_pdf.py
  - Dashboard          → /api/pipeline/summary and related endpoints

Verdict logic
-------------
FAIL  : any component has severity CRITICAL or HIGH, OR any vulnerability
        has an EPSS score above the escalation threshold.
WARN  : vulnerabilities exist but none reach FAIL criteria; also triggered
        when any severity is UNKNOWN (score unavailable, risk unquantifiable).
PASS  : no vulnerabilities found.
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from .vuln_checker import ScanResult, SEVERITY_ORDER
from .epss_checker import EPSS_ESCALATION_THRESHOLD

logger = logging.getLogger(__name__)


def _verdict(results: list[ScanResult]) -> str:
    """
    Compute the overall pipeline verdict from a list of scan results.

    Iterates all vulnerable components; returns on the first FAIL condition
    to avoid unnecessary work.
    """
    for r in results:
        if r.highest_severity in ("CRITICAL", "HIGH"):
            return "FAIL"
        # EPSS escalation: a MEDIUM/LOW vuln being actively exploited is FAIL
        for v in r.vulns:
            if v.epss_score is not None and v.epss_score >= EPSS_ESCALATION_THRESHOLD:
                return "FAIL"

    # UNKNOWN severity means the score wasn't available — flag as WARN so it
    # doesn't silently disappear in a PASS verdict
    if any(v.severity == "UNKNOWN" for r in results for v in r.vulns):
        return "WARN"

    return "WARN" if any(r.is_vulnerable for r in results) else "PASS"


def build_report(results: list[ScanResult], target_dir: str) -> dict:
    """
    Assemble the security report dict from vuln_checker results.

    Vulnerable components are sorted by highest severity (CRITICAL first).
    Vulnerabilities within each component are also sorted by severity.
    The extended_coverage section (extended_coverage key) is added by the caller after this
    function returns, so it is not included here.
    """
    vulnerable = [r for r in results if r.is_vulnerable]
    skipped    = [r for r in results if r.error]

    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    for r in vulnerable:
        for v in r.vulns:
            if v.severity in severity_counts:
                severity_counts[v.severity] += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target":       target_dir,
        "verdict":      _verdict(results),
        "summary": {
            "total":       len(results),
            "vulnerable":  len(vulnerable),
            "skipped":     len(skipped),
            "total_vulns": sum(len(r.vulns) for r in vulnerable),
            "by_severity": severity_counts,
        },
        "vulnerable_components": [
            {
                "name":             r.component.name,
                "version":          r.component.version,
                "ecosystem":        r.component.ecosystem,
                "highest_severity": r.highest_severity,
                "max_cvss":         r.max_cvss,
                "max_epss":         r.max_epss,
                "vulns": [
                    {
                        "id":              v.id,
                        "source":          v.source,
                        "severity":        v.severity,
                        "cvss":            v.cvss_score,
                        "epss":            v.epss_score,
                        "epss_percentile": v.epss_percentile,
                        "summary":         v.summary,
                        "fixed":           v.fixed_version,
                        "affects_from":       v.affects_from,
                        "affects_before":     v.affects_before,
                        "version_confirmed":  v.version_confirmed,
                        "vdb_id":             getattr(v, "vdb_id", None),
                        "exploit_available":  getattr(v, "exploit_available", False),
                    }
                    # Sort vulns within a component by severity (most severe first)
                    for v in sorted(
                        r.vulns,
                        key=lambda v: SEVERITY_ORDER.index(v.severity)
                                      if v.severity in SEVERITY_ORDER else 99,
                    )
                ],
            }
            # Sort components by highest severity (most severe first)
            for r in sorted(
                vulnerable,
                key=lambda r: SEVERITY_ORDER.index(r.highest_severity)
                              if r.highest_severity in SEVERITY_ORDER else 99,
            )
        ],
        "skipped": [
            {"name": r.component.name, "reason": r.error}
            for r in skipped
        ],
    }


def save_report(report: dict, path: str | Path) -> Path:
    """Write the report dict to *path* as indented JSON.  Creates parent dirs."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    logger.info(f"Report saved: {path}")
    return path


def print_report(report: dict) -> None:
    """Print a human-readable summary to stdout.  Uses Rich if available."""
    try:
        _print_rich(report)
    except ImportError:
        _print_plain(report)


def _print_rich(report: dict) -> None:
    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console()
    verdict = report["verdict"]
    color   = {"PASS": "green", "WARN": "yellow", "FAIL": "red"}.get(verdict, "white")
    s       = report["summary"]

    console.print()
    console.print(
        f"[bold {color}]{verdict}[/bold {color}]  "
        f"[dim]{s['total']} components — {s['total_vulns']} vulnerabilities[/dim]"
    )

    sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "UNKNOWN": "⚪"}
    parts = [f"{sev_emoji[k]} {k}: {v}" for k, v in s["by_severity"].items() if v]
    if parts:
        console.print("  " + "  |  ".join(parts))
    console.print()

    if not report["vulnerable_components"]:
        console.print("[green]✓ No vulnerabilities found.[/green]")
        return

    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column("Package",  style="cyan")
    table.add_column("Version",  style="magenta")
    table.add_column("Severity")
    table.add_column("CVSS")
    table.add_column("EPSS")
    table.add_column("Vuln IDs")
    table.add_column("Fix")

    sev_color  = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow",
                  "LOW": "green", "UNKNOWN": "white"}
    epss_color = lambda s: "red" if s >= EPSS_ESCALATION_THRESHOLD else ("yellow" if s >= 0.2 else "green")

    for comp in report["vulnerable_components"]:
        sev  = comp["highest_severity"] or "?"
        has_exploit = any(v.get("exploit_available") for v in comp["vulns"])
        ids  = ", ".join(v["id"] for v in comp["vulns"][:3])
        if len(comp["vulns"]) > 3:
            ids += f" (+{len(comp['vulns']) - 3})"
        if has_exploit:
            ids = "[red]⚡[/red] " + ids
        fixes    = {v["fixed"] for v in comp["vulns"] if v["fixed"]}
        epss     = comp.get("max_epss")
        epss_str = (
            f"[{epss_color(epss)}]{epss:.3f}[/{epss_color(epss)}]"
            if epss is not None else "—"
        )
        table.add_row(
            comp["name"], comp["version"],
            f"[{sev_color.get(sev, 'white')}]{sev}[/{sev_color.get(sev, 'white')}]",
            f"{comp['max_cvss']:.1f}" if comp["max_cvss"] else "—",
            epss_str,
            ids,
            ", ".join(sorted(fixes)) if fixes else "—",
        )
    console.print(table)

    if report["skipped"]:
        console.print(f"\n[dim]⚠ {len(report['skipped'])} components skipped[/dim]")

    detected = report.get("detected", [])
    if detected:
        console.print(f"\n[yellow]⚠ {len(detected)} OT component(s) detected but not analyzed (no PURL):[/yellow]")
        for d in detected:
            console.print(f"  [dim]{d['name']} [{d['category']}/{d['confidence']}] — {d['reason']}[/dim]")

    indirect = report.get("indirect_components", [])
    if indirect:
        names = ", ".join(c["name"] for c in indirect[:5])
        extra = f" +{len(indirect) - 5} more" if len(indirect) > 5 else ""
        console.print(
            f"\n[dim]ℹ {len(indirect)} transitive/indirect component(s) excluded from scan: "
            f"{names}{extra}  (use --include-indirect to scan them)[/dim]"
        )
    console.print()


def _print_plain(report: dict) -> None:
    s = report["summary"]
    print(f"\n{'='*50}")
    print(f"VERDICT: {report['verdict']}  |  {s['total']} components  |  {s['total_vulns']} vulns")
    for sev, count in s["by_severity"].items():
        if count:
            print(f"  {sev}: {count}")
    for comp in report["vulnerable_components"]:
        print(f"\n  {comp['name']} {comp['version']} [{comp['highest_severity']}]")
        for v in comp["vulns"]:
            epss_str    = f"  EPSS={v['epss']:.3f}" if v.get("epss") is not None else ""
            exploit_str = "  [EXPLOIT]" if v.get("exploit_available") else ""
            vdb_str     = f"  {v['vdb_id']}" if v.get("vdb_id") else ""
            print(f"    - {v['id']} [{v['severity']}] CVSS={v['cvss'] or '?'}{epss_str}{exploit_str}{vdb_str}: {v['summary']}")
            if v["fixed"]:
                print(f"      fix: {v['fixed']}")
    detected = report.get("detected", [])
    if detected:
        print(f"\n  DETECTED (unanalyzable):")
        for d in detected:
            print(f"    - {d['name']} [{d['category']}/{d['confidence']}] reason={d['reason']}")
    indirect = report.get("indirect_components", [])
    if indirect:
        names = ", ".join(c["name"] for c in indirect[:5])
        extra = f" +{len(indirect) - 5} more" if len(indirect) > 5 else ""
        print(f"\n  INDIRECT (excluded): {names}{extra}")
    print(f"{'='*50}\n")
