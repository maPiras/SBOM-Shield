"""
CSAF 2.0 JSON document → normalised vendor advisory records.

We extract only what SC4 needs: per (advisory, CVE) tuple, the publisher's
own CVSS + severity verdict, plus the list of vendor product names affected.
The full product_tree is flattened to a dict[product_id → display_name] just
so that affected_products is human-readable; nothing depends on the tree
structure being preserved.

This module is pure-Python, no I/O, no caching. Feed loaders call into it.
"""
from __future__ import annotations

from typing import Iterator


_CVSS_KEYS = ("cvss_v31", "cvss_v3", "cvss_v40")


def _flatten_branches(branches: list, products: dict) -> None:
    """Walk a CSAF product_tree.branches recursively; collect product_id → name."""
    for b in branches or []:
        product = b.get("product")
        if product and "product_id" in product:
            products[product["product_id"]] = product.get("name") or product["product_id"]
        if b.get("branches"):
            _flatten_branches(b["branches"], products)


def _flatten_product_tree(tree: dict) -> dict[str, str]:
    products: dict[str, str] = {}
    _flatten_branches(tree.get("branches", []), products)
    # Some CSAF docs put products directly at top level
    for p in tree.get("full_product_names", []) or []:
        pid = p.get("product_id")
        if pid:
            products[pid] = p.get("name") or pid
    return products


def _extract_vendor_score(vuln: dict) -> tuple[float | None, str | None]:
    """Highest CVSS across all `scores[]` entries on this vulnerability."""
    max_score = -1.0
    sev = None
    for s in vuln.get("scores", []) or []:
        for key in _CVSS_KEYS:
            cvss = s.get(key)
            if not cvss:
                continue
            base = cvss.get("baseScore")
            if isinstance(base, (int, float)) and base > max_score:
                max_score = float(base)
                sev = cvss.get("baseSeverity")
            break
    return (max_score if max_score >= 0 else None, sev)


def _extract_cve_id(vuln: dict) -> str | None:
    """CSAF stores the CVE either as v["cve"] or under v["ids"][*]."""
    cve = vuln.get("cve")
    if cve and cve.startswith("CVE-"):
        return cve
    for entry in vuln.get("ids", []) or []:
        text = entry.get("text") or ""
        if text.startswith("CVE-"):
            return text
    return None


def parse_document(doc: dict) -> Iterator[dict]:
    """Yield one record per (advisory, CVE) pair found in the document.

    Output fields:
      advisory_id, publisher, release_date, cve_id,
      vendor_cvss, vendor_severity, affected_products[list[str]],
      title (advisory-level), tlp_label
    """
    document = doc.get("document", {}) or {}
    tracking = document.get("tracking", {}) or {}
    publisher = document.get("publisher", {}) or {}
    distribution = document.get("distribution", {}) or {}
    tlp = (distribution.get("tlp") or {}).get("label")

    advisory_id  = tracking.get("id") or ""
    release_date = tracking.get("current_release_date") or tracking.get("initial_release_date") or ""
    title        = document.get("title") or ""
    pub_name     = publisher.get("name") or ""

    products = _flatten_product_tree(doc.get("product_tree", {}) or {})

    for v in doc.get("vulnerabilities", []) or []:
        cve = _extract_cve_id(v)
        if not cve:
            continue
        score, sev = _extract_vendor_score(v)
        affected_ids = (v.get("product_status", {}) or {}).get("known_affected", []) or []
        affected_names = [products.get(pid, pid) for pid in affected_ids]
        yield {
            "advisory_id":      advisory_id,
            "publisher":        pub_name,
            "release_date":     release_date,
            "title":            title,
            "tlp_label":        tlp,
            "cve_id":           cve,
            "vendor_cvss":      score,
            "vendor_severity":  sev,
            "affected_products": affected_names,
        }
