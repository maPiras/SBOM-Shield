"""
core.extended_coverage — OT/ICS static analysis layer.

Public API
----------
    from core.extended_coverage import run, enrich

    ec_result = run("/path/to/project")   # → OTScanResult
    enrich_res = enrich(components, ec_result)
"""
from .detectors import run
from .models import enrich, OTScanResult, OTComponent, EnrichmentResult

__all__ = ["run", "enrich", "OTScanResult", "OTComponent", "EnrichmentResult"]
