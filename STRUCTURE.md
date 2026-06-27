# STRUCTURE — Claude navigation map

Reference for any future Claude session working in this repo. Every file below
has a one-line purpose and the concrete key names to grep for. Use this as the
first read after `README.md` (and, when applicable, the Overleaf-managed
thesis-positioning document).

---

## 0. Authoritative documents (read first)

| File | What to read it for |
|------|---------------------|
| `README.md` | User-facing pitch: features, quickstart, pipeline diagram. |
| `STRUCTURE.md` | This file — the map. |
| `notes/README.md` | Index of engineering notes (issues, detection, filtering, priority, future, regulatory). |
| `notes/priority.md` | Priority engine design + SC4 validation method + CSAF join inventory + W1–W4 status. |
| **POSITIONING.md** | Thesis scope and contribution claims C1–C6. **Lives in Overleaf**, not in this repo. Notes refer to its §3/§4/§9/§10. Do not propose work outside that scope without flagging it. |

---

## 1. Repository tree (elided)

```
sbom-shield/
├── main.py                         CLI entry point — supports --sbom-file flow
├── README.md / STRUCTURE.md
├── install.sh                      systemd + nginx installer
├── .env.example                    env vars (NVD_API_KEY, VULDB_API_KEY,
│                                    SBOMSHIELD_SECRET, SBOMSHIELD_REPOS_DIR, …)
├── requirements.txt                Python deps (fastapi, httpx, bcrypt, jwt,
│                                    tree-sitter, pyyaml, pydantic)
│
├── api/
│   └── server.py                   FastAPI app — auth, dashboard endpoints,
│                                    scan/track CRUD, SSE progress stream
│
├── core/                           All analysis logic
│   ├── pipeline.py                 ★ run_pipeline() — shared by SSE worker,
│   │                                tracking scheduler, eval benchmark
│   ├── tracking.py                 ★ Background scheduler for periodic
│   │                                re-scans on tracked projects
│   │
│   ├── sbom_generator.py           Orchestrator: cdxgen primary + Syft fill-in → merged CycloneDX
│   ├── cdxgen_runner.py            Wraps cdxgen (offline-default; --online-resolution opt-in)
│   ├── syft_runner.py              Wraps syft (secondary; skipped via --no-syft-fallback)
│   ├── sbom_merger.py              Merge cdxgen+syft; cdxgen wins on PURL/(name,version) conflict
│   ├── sbom_parser.py              CycloneDX JSON → list[Component]; reads sbom-shield:source property
│   ├── requirements_parser.py      Lower-bound extraction from requirements.txt / pyproject / package.json
│   ├── vuln_checker.py             MAIN vuln scanner — OSV + NVD + VulDB + KEV + EPSS (5 phases)
│   ├── vuldb_checker.py            VulDB side-integration (CVE + exploit_available)
│   ├── epss_checker.py             Loads FIRST EPSS CSV index
│   ├── report_generator.py         Build report dict, FAIL/WARN/PASS legacy verdict, save JSON
│   │
│   ├── extended_coverage/          OT/ICS static-analysis layer (11 registered detectors)
│   │   ├── __init__.py             Public API: run(), enrich()
│   │   ├── detectors.py            Orchestrator: ThreadPoolExecutor over 11 detectors + dedup + version enrichment + call verification
│   │   ├── scanners.py             6 original detectors (protocols, rtos, bsp, plc_scada, device_desc, build_manifest) + FileIndex. NOTE: plc_scada is implemented here but NOT registered — see §5 gotchas / issues.md #6.
│   │   ├── build_detectors.py      5 extra detectors (autoconf, esp_idf_manifest, zephyr_manifest, compile_commands, cmake_link_libs)
│   │   ├── elf_detector.py         readelf DWARF extraction from .elf/.axf firmware
│   │   ├── version_extractor.py    Post-dedup version enrichment (strings, hex macros, .pc, CMakeCache)
│   │   ├── conan_parser.py         Non-standard Conan manifests (conan_reqs.txt, conan.lock.*)
│   │   └── models.py               Dataclasses + _PURL_MAP (45+ entries) + enrich()
│   │
│   ├── noise_filter/               Post-detection CVE noise reduction
│   │   ├── __init__.py             Public API: tag, verify_calls
│   │   ├── signatures.py           ★ Shared per-library signature pack (includes/cmake/imports/calls) consumed by both modules
│   │   ├── reachability.py         tag() — directly_used flag per component (signature-driven + generic fallback)
│   │   └── call_verifier.py        verify_calls() — tree-sitter C/C++ AST call-site check (rules derived from signatures)
│   │
│   ├── priority/                   ★ SSVC-extended priority engine (contribution C1/C2)
│   │   ├── __init__.py             Public API: prioritize(report, profile)
│   │   ├── models.py               Pydantic: ContextProfile, SSVCInputs, Priority, PriorityBreakdown
│   │   ├── ssvc.py                 Decision tree (Active/Public PoC/None × Open/Controlled/Small → bucket)
│   │   ├── scoring.py              Intra-bucket weighted formula + ALPHA..EPSILON + _CRIT_WEIGHT
│   │   ├── profiles.py             4 built-in presets + load_profile() + YAML loader
│   │   └── profiles/               (reserved for per-domain YAML overrides)
│   │
│   └── csaf/                       ★ CSAF 2.0 ingestion + advisory cache
│       ├── __init__.py             Public API: refresh(feed, max_docs), get_for_cves(), stats()
│       ├── feeds.py                Siemens ProductCERT + CISA ICS-CERT loaders (8-worker pool)
│       ├── parser.py               CSAF 2.0 JSON → {advisory_id, publisher, cve_id, vendor_cvss, …}
│       └── storage.py              SQLite csaf_advisories table (lives inside scans.db)
│
├── storage/
│   ├── database.py                 SQLite schema + save/load for scans, components,
│   │                                vulns, users, **tracks**, **csaf_advisories**
│   ├── scans.db                    Runtime database (WAL mode) — holds CSAF cache too
│   └── seed_db.py                  Creates default admin user / demo data
│
├── dashboard/
│   ├── public/                     Static files served by nginx (NOT by FastAPI)
│   │   ├── index.html / main.js / style.css      Landing page
│   │   ├── dashboard/user.html                   Authenticated SPA (Babel-standalone JSX)
│   │   └── assets/                               SVG/PNG branding
│   ├── app/                        (empty placeholder)
│   ├── uploads/                    User-uploaded targets
│   └── logs/                       Scan logs
│
├── eval/                           ★ Empirical validation (SC4)
│   ├── run_benchmark.py            Batch scanner over the 14-repo pool (production_ot profile, --no-syft-fallback)
│   ├── sc4_metrics.py              Spearman ρ + Cohen κ + per-publisher/per-component cuts
│   ├── tune_weights.py             Grid-search tuner for (α β γ δ ε), train/test split seed=42
│   └── results/                    Per-repo + _summary.json + sc4_report.json + sc4_tuning.json
│
├── reports/                        Generated JSON artefacts
│   ├── sbom.json                   Last CycloneDX SBOM
│   └── security_report.json        Last full report
│
├── assets/                         Repo-level images (architecture diagram, logo)
│
└── notes/                          Engineering notes — see notes/README.md
    ├── README.md
    ├── issues.md                   Open bugs (NVD FP, CPE nested nodes, plc_scada unregistered, …)
    ├── detection.md                Tiers, 11 detectors, signature strategy, Conan fix, binary path
    ├── filtering.md                reachability + call_verifier + qt_modules split-and-map plan
    ├── priority.md                 Priority engine design, CSAF join (50-component inventory), SC4 results, W1–W4 status
    ├── signature_pack.txt          Why noise_filter/signatures.py exists, 34-entry inventory, operational change, follow-ups
    ├── future.md                   Prioritised backlog
    └── regulatory.md               CRA, NIS2, FDA, EO 14028, IEC 62443, EPSS, CSAF
```

Deployment note: nginx serves `dashboard/public/`; FastAPI lives at
`/opt/sbom-shield/backend` (systemd); scanner at `/opt/sbom-shield/scanner`.
Development copy lives here at `/home/debian/sbom-shield`.

---

## 2. Pipeline

There are **two entry points** sharing the same downstream stages:

- **`main.py`** — CLI. Keeps its own flow because it supports `--sbom-file`
  (pre-generated SBOM) which `run_pipeline()` does not model. Calls
  `prioritize()` at the end so its reports still carry a `priority` block.
- **`core/pipeline.run_pipeline()`** — shared by:
  - `api/server.py` SSE worker (POST `/api/scan/run` + GET `/api/scan/stream/{id}`)
  - `core/tracking.py` scheduler (periodic re-scans)
  - `eval/run_benchmark.py` (batch benchmark)

Downstream stages (both flows):

```
target dir
   │
   ▼  1.  sbom_generator.generate_sbom(dir)            cdxgen → CycloneDX dict
   │       └─ + syft (if available, --no-syft-fallback to skip)
   │       └─ sbom_merger.merge — cdxgen wins; syft adds only what cdxgen missed
   │
   ▼  2.  sbom_parser.parse_sbom(dict)                 → list[Component] (with .source)
   │
   ▼  3a. requirements_parser.enrich_components()      adds manifest-declared deps Syft missed
   │
   ▼  3b. extended_coverage.conan_parser.enrich()      adds Conan deps Syft doesn't understand
   │
   ▼  4.  extended_coverage.run(target)                OT/ICS static analysis
   │      │
   │      ├─ FileIndex built once
   │      ├─ 11 detectors in parallel (ThreadPoolExecutor, 6 workers)
   │      ├─ dedup by category::name
   │      ├─ build_manifest cross-reference (upgrade source_type unknown→remote)
   │      ├─ version_extractor.enrich_versions()
   │      └─ noise_filter.call_verifier.verify_calls() (C/C++ only, upgrades MEDIUM→HIGH)
   │
   ▼  4b. extended_coverage.enrich(components, ec_result)  inject OT comps (≥MEDIUM, parseable PURL)
   │
   ▼  4c. noise_filter.reachability.tag(components, dir)   sets directly_used per component
   │      (unless --include-indirect, indirect components are dropped before vuln scan)
   │
   ▼  5.  vuln_checker.scan(components)
   │      │
   │      ├─ Phase 0    KEV prefetch + EPSS index (parallel)
   │      ├─ Phase 1    OSV queries (parallel, OSV_WORKERS)
   │      ├─ Phase 1b   NVD keyword for augment_injected pkg:github/
   │      ├─ Phase 1c   NVD keyword for augment_injected pkg:generic/
   │      ├─ Phase 1d   NVD keyword for Conan packages OSV missed
   │      ├─ Phase 1e   VulDB discovery + exploit enrichment (optional, VULDB_API_KEY)
   │      ├─ Phase 2a   CISA KEV membership flag
   │      ├─ Phase 2b   NVD CVSS fill-in (parallel, NVD_WORKERS)
   │      └─ Phase 3    EPSS scoring
   │
   ▼  6.  report_generator.build_report()              legacy FAIL/WARN/PASS verdict; JSON dict
   │
   ▼  7.  priority.prioritize(report, context_profile) ★ SSVC bucket + intra-bucket score
   │      per vuln + per-component max, plus report["priority"] aggregate
   │
   ▼  8.  storage.database.save_scan()                 persist to SQLite
   │      (main.py POSTs to /api/internal/scan/save; pipeline flow inlines)
   │
   └→ stdout summary + reports/security_report.json
```

Exit codes (`main.py`): 0 = clean, 1 = vuln ≥ `--fail-on`, 2 = fatal.

The `priority` block is **additive metadata**; the legacy `verdict`
(`report_generator._verdict`) is still the gate that drives `--fail-on`.

---

## 3. Key types (condensed)

### `core/sbom_parser.Component`
```
name, version, purl, ecosystem                 # base fields
extended_injected: bool                         # True if from extended_coverage
directly_used: bool = True                      # set by noise_filter.reachability
source: str | None                              # cdxgen | syft | manifest | conan | extended_coverage
```

### `core/extended_coverage/models.OTComponent`
```
name, version: str|None, purl: str|None
category: FIELDBUS | PROTOCOL_STACK | RUNTIME | RTOS | BSP_HAL | SCADA_HMI | DEVICE_DESC | UNKNOWN
matches: list[DetectionMatch]                   # capped to first 5 in to_dict()
confidence: HIGH | MEDIUM | LOW
source_type: unknown | vendored | remote | linked | verified
key property: f"{category}::{name}"             # dedup key
```

### `core/extended_coverage/models.DetectionMatch`
```
file_path, line_number, matched_text (≤120 chars)
detection_type: import | config_file | build_system | project_file | device_desc | build_manifest | api_call
```

### `core/extended_coverage/models._PURL_MAP`  (45+ entries)
`{lowercase_key: (purl_base, canonical_display_name)}`. PURL types:
`pkg:pypi/` (OSV), `pkg:npm/` (OSV), `pkg:github/` (NVD 1b), `pkg:generic/` (NVD 1c).

### `core/vuln_checker.Vulnerability`
```
id, aliases, severity: CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN
cvss_score, epss_score, in_kev: bool, source
affects_from, affects_before, version_confirmed: bool
vdb_id, exploit_available                       # from VulDB
```

### `core/priority/models.ContextProfile`  (Pydantic)
```
name:                str             # free-form label
exposure:            airgapped | local | network
criticality:         safety_critical | production | lab | dev
update_cadence_days: int (1..10000)              # only enters SSVC impact, never the formula
```

### `core/priority/models.SSVCInputs`
```
exploitation: None | "Public PoC" | "Active"
exposure:     Small | Controlled | Open
utility:      Laborious | Efficient | "Super Effective"
impact:       Low | Medium | High | "Very High"
```

### `core/priority/models.Priority`  (attached to each vuln)
```
bucket:    "Act" | "Attend" | "Track*" | "Track"
score:     0.0–1.0
rationale: "Act: exploitation=Active, exposure=Open, …"
breakdown: PriorityBreakdown(ssvc_inputs, formula_terms)
```

### Legacy verdict (`report_generator._verdict`)
```
FAIL  — any CRITICAL/HIGH, OR any EPSS ≥ EPSS_ESCALATION_THRESHOLD
WARN  — any vuln, OR any UNKNOWN severity
PASS  — no vulns
```

`priority` is **additive**; the legacy verdict has not been replaced.

---

## 4. Grep cheatsheet — "where does X live?"

### Core pipeline

| Looking for | File | Symbol |
|-------------|------|--------|
| Shared pipeline entry | `core/pipeline.py` | `run_pipeline()` |
| SBOM orchestrator | `core/sbom_generator.py` | `generate_sbom()`, `GenerationResult` |
| cdxgen invocation | `core/cdxgen_runner.py` | `generate()`, `_TIMEOUT=600` |
| Syft invocation | `core/syft_runner.py` | `generate()`, `_TIMEOUT=300` |
| SBOM merge logic | `core/sbom_merger.py` | `merge()`, `MergeStats`, `_canonical_purl()` |
| CycloneDX → Component | `core/sbom_parser.py` | `parse_sbom()`, `ECOSYSTEM_MAP`, `_SOURCE_PROPERTY` |
| OSV query | `core/vuln_checker.py` | Phase 1; `_osv_query()` |
| NVD keyword search | `core/vuln_checker.py` | `_nvd_keyword_search()`, `_nvd_product_name()` (issues.md #1) |
| NVD CPE range filter | `core/vuln_checker.py` | `_extract_cpe_range()`, `_version_in_range()` (issues.md #2) |
| VulDB | `core/vuldb_checker.py` | `scan()` |
| KEV check | `core/vuln_checker.py` | `_kev_prefetch()`, Phase 2a |
| EPSS scoring | `core/epss_checker.py` | `load_epss_index()`, `EPSS_ESCALATION_THRESHOLD` |
| Legacy verdict | `core/report_generator.py` | `_verdict()` |

### Detection layer

| Looking for | File | Symbol |
|-------------|------|--------|
| OT detector orchestrator | `core/extended_coverage/detectors.py` | `run()`, `_COMPONENT_DETECTORS` |
| 27 protocol import rules | `core/extended_coverage/scanners.py` | `_PROTO_IMPORT_RULES` |
| 25 RTOS rules | `core/extended_coverage/scanners.py` | inside `detect_rtos` |
| PLC library refs (unregistered) | `core/extended_coverage/scanners.py` | `detect_plc_scada`, `_PLC_LIB_RXS`, `_KNOWN_PLC_LIBS` |
| Git submodule URL map | `core/extended_coverage/scanners.py` | `_GITMODULE_URL_MAP` (30 fragments) |
| Vendored header version | `core/extended_coverage/scanners.py` | `_version_from_vendored_header()` |
| 5 new build detectors | `core/extended_coverage/build_detectors.py` | `detect_autoconf`, `detect_esp_idf_manifest`, `detect_zephyr_manifest`, `detect_compile_commands`, `detect_cmake_link_libs` |
| ELF DWARF extraction | `core/extended_coverage/elf_detector.py` | `detect_elf_binaries()`, `_BUILD_RX`, `_CMAKE_RX`, `_ZEPHYR_RX` |
| Post-dedup version enrich | `core/extended_coverage/version_extractor.py` | `enrich_versions()` |
| Conan custom parser | `core/extended_coverage/conan_parser.py` | `enrich_components()`, `_LOCK_ENTRY_RE` |
| OT PURL map | `core/extended_coverage/models.py` | `_PURL_MAP` |
| OT→SBOM injection | `core/extended_coverage/models.py` | `enrich()` |
| Call-site verification | `core/noise_filter/call_verifier.py` | `verify_calls()`, `_CALL_RULES` (derived from signatures) |
| Direct-usage tagging | `core/noise_filter/reachability.py` | `tag()`, `_signature_hit()`, `_has_api_call_evidence()` |
| Shared signature pack | `core/noise_filter/signatures.py` | `SIGNATURES`, `signature_for()`, `call_rules()` |

### Priority engine

| Looking for | File | Symbol |
|-------------|------|--------|
| Public entry | `core/priority/__init__.py` | `prioritize()`, `BUCKET_ORDER` |
| SSVC decision tree | `core/priority/ssvc.py` | `evaluate()`, `bucket()`, `rationale()`, `_EPSS_*_THRESHOLD`, `_IMPACT_BASE` |
| Weighted formula | `core/priority/scoring.py` | `score()`, `ALPHA`, `BETA`, `GAMMA`, `DELTA`, `EPSILON`, `_CRIT_WEIGHT` |
| Built-in presets | `core/priority/profiles.py` | `PRESETS`, `DEFAULT_PRESET`, `load_profile()`, `load_yaml()` |
| Schemas | `core/priority/models.py` | `ContextProfile`, `SSVCInputs`, `Priority`, `PriorityBreakdown` |

### CSAF + tracking + evaluation

| Looking for | File | Symbol |
|-------------|------|--------|
| CSAF public API | `core/csaf/__init__.py` | `refresh()`, `get_for_cves()`, `stats()` |
| Siemens / CISA feeds | `core/csaf/feeds.py` | `SiemensFeed`, `CisaIcsFeed`, `FEEDS` |
| CSAF 2.0 parser | `core/csaf/parser.py` | `parse_document()` |
| CSAF SQLite cache | `core/csaf/storage.py` | `init_schema()`, `upsert()`, `get_by_cve()` |
| Tracking scheduler | `core/tracking.py` | `start_scheduler()`, `stop_scheduler()`, `run_track_now()`, `POLL_INTERVAL_SECONDS` |
| Benchmark batch | `eval/run_benchmark.py` | (production_ot, `--no-syft-fallback`) |
| ρ / κ metrics | `eval/sc4_metrics.py` | Mapping B (`Critical→Act`, `High→Act`, …) |
| Weight tuner | `eval/tune_weights.py` | grid step 0.10, seed=42, ≥0.05 Δρ acceptance |

### API + storage

| Looking for | File | Symbol |
|-------------|------|--------|
| FastAPI app | `api/server.py` | `app = FastAPI(...)`, `SBOMSHIELD_SECRET`, `SBOMSHIELD_REPOS_DIR` |
| Scan SSE stream | `api/server.py` | `@app.get("/api/scan/stream/{scan_id}")`, `_scan_queues` |
| Tracking endpoints | `api/server.py` | `/api/tracks*` (CRUD), `/api/priority/presets` |
| SQLite schema | `storage/database.py` | `_SCHEMA`, `_EXTRA_TABLES`, `_MIGRATIONS` |
| Scan persistence | `storage/database.py` | `save_scan()`, `get_scan_detail()`, `get_summary()` |
| Track persistence | `storage/database.py` | `create_track()`, `get_track()`, `get_due_tracks()`, `update_track_after_scan()`, `upgrade_track_version()`, `disable_track()`, `delete_track()`, `list_tracks()`, `get_track_history()` |

### API endpoints (`api/server.py`)
```
POST   /api/v1/auth/login
GET    /api/v1/auth/me
GET    /api/pipeline/summary
GET    /api/scans/recent
GET    /api/vulns/severity-breakdown
GET    /api/sources/stats
GET    /api/vulns/trend
GET    /api/kev/active
GET    /api/scans/search
GET    /api/scans/{scan_id}/detail
GET    /api/repos
POST   /api/scan/run                          (accepts version + context_profile)
GET    /api/scan/stream/{scan_id}             SSE progress stream
POST   /api/ot/analyze
POST   /api/internal/scan/save                called by main.py

GET    /api/priority/presets                  {default, presets:{name: ContextProfile}}

GET    /api/tracks
GET    /api/tracks/{track_id}                 includes history[]
POST   /api/tracks                            create + immediate first scan
POST   /api/tracks/{track_id}/upgrade         flip current_version + re-scan
POST   /api/tracks/{track_id}/disable
DELETE /api/tracks/{track_id}                 soft-detach: scans.track_id ← NULL
```

### SQLite schema (`storage/database.py`)
```
scans                    + version, track_id, context_profile_json, priority_json,
                          priority_{act,attend,trackstar,track}_count          (additive migrations)
vulnerable_components    name, version, ecosystem, highest_severity, max_cvss, max_epss
vulnerabilities          vuln_id, source, severity, cvss/epss/percentile, summary, fixed_version
skipped_components       name, reason
users                    email, password_hash, is_admin
tracks                   project_name, repo_path, current_version,
                          context_profile_json, interval_hours, enabled,
                          last_check_at, last_scan_id, options_json
csaf_advisories          (created by core/csaf/storage.py — UNIQUE(advisory_id, cve_id))
```

Indices: `idx_scans_*`, `idx_vulns_*`, `idx_comps_scan_id`, `idx_tracks_enabled`,
`idx_tracks_last_check`, `idx_scans_track_id`.

---

## 5. Status & gotchas (as of 2026-05-23)

### Project status
- **W1 ✓** (2026-05-12) — Pydantic schemas + priority engine + GUI panel + tracking scheduler + unified `core/pipeline.py`.
- **W2 ✓** (2026-05-12) — `core/csaf/` parser + feeds + storage; full mirror cached (Siemens + CISA, 5964 unique CVEs).
- **W3 ✓** (2026-05-17) — Full 14-repo benchmark closed. Headline: ρ = 0.9511 on intra-bucket score vs vendor CVSS (n=17 pairs, 5 unique CVEs); κ = 0 / bucket-agreement = 0 %. Tuner: Δρ_test = 0 → KEEP DEFAULTS. Disposition: bucket divergence is intentional semantic drift (exploitation-driven vs severity-driven).
- **W4 next** — engine tuning on W3 gaps, component DB → 40 entries, follow-ups: CVE-ID alias collapse to widen the CSAF join; Schneider Electric SE feed; evaluate "vendor advisory exists" as third Exploitation tier before any SSVC code change.
- **W5–W6** — Thesis writing.

### Concrete gotchas
- **`detect_plc_scada` is implemented in `scanners.py` but NOT in `_COMPONENT_DETECTORS`** — current registry has 5 (protocols, rtos, bsp, device_desc, build_manifest) + 5 (autoconf, esp_idf_manifest, zephyr_manifest, compile_commands, cmake_link_libs) + 1 (elf_binaries) = 11. PLC/SCADA findings currently come via `detect_protocols` + `detect_build_manifest`. See `notes/issues.md` #6.
- **CSAF cache lives inside `storage/scans.db`** — same SQLite file as scans. Don't copy `scans.db` around without taking the whole file; the cache is inside.
- **Benchmark uses `--no-syft-fallback`** (set in `eval/run_benchmark.py`) to keep batch fast. Don't change without re-running the whole batch.
- **`production_ot` profile drives the SC4 benchmark** — most permissive context, maximises bucket-distribution spread; `safety_critical_ot` would bump almost everything to Act, `lab_research` would drop almost everything to Track*.
- **Dashboard JSX is Babel-standalone in-browser** — `dashboard/public/dashboard/user.html` must keep brace/paren counts balanced; Babel errors are silent (UI just shows "INITIALISING…"). Last known good: braces 837/837, parens 691/691.
- **`reachability.tag` concatenates all source into a single string** — correct but slow on Zephyr-scale trees (~1.4 GB, ~45 min CPU). Backlog: streaming match.
- **NVD rate limit** — ~5 req/30 s without API key, ~50 with. `core/vuln_checker.py` now reads `NVD_API_KEY` from env (sends `apiKey` header, bumps to 8 workers / 0.7 s pacing). Key lives in gitignored `.env` (NOT `.env.example` — that's tracked); pipeline does not auto-load `.env`, so run with `set -a; source .env; set +a` first. Retries on 429/502/503/504 AND timeouts (`_NVD_RETRY_CODES`). Keyless runs are unstabilizable for the benchmark (503s→timeouts zero late repos).
- **Version-anchored / keyword-unreliable libs** (`core/vuln_checker.py`): `_VERSION_ANCHORED_KEYWORD_LIBS = {openssl, wolfssl, zlib}` skip the NVD keyword search when no version was recovered (version-less keyword returns ALL historical CVEs — openssl 546). `_KEYWORD_UNRELIABLE_LIBS = {qt}` always skip (monolithic CPE + "qt"↔QNAP "QTS" collision → false KEV→Act). Both keep the component in the DB/coverage; only the vuln lookup is suppressed. Scoped narrowly so mbedTLS/ThreadX/FreeRTOS (also version-less keyword libs) are NOT affected — they drive the SC4 CSAF join.
- **Qt monolithic component floods CVEs** — a single `#include <Q*>` flips the entire `qt` PURL to `directly_used=True`; its keyword lookup is now suppressed (see above) as an interim control, but per-module PURL decomposition is still unsolved (`notes/filtering.md` "qt_modules split-and-map").
- **Reachability is now strict for components in the signature pack** (`core/noise_filter/signatures.py`, **40 entries** as of W4). For those libs, signature-miss flips `directly_used = False` instead of the conservative-True default. Manifest direct-deps (Conan / pip / `api_call` evidence from call_verifier) still override. Background in `notes/signature_pack.txt`. **W4 (2026-06-24) re-ran the full clean key'd 14-repo benchmark — `eval/results/` is current**; SC4 ρ=0.9511/κ=0/Δρ=0 (unchanged), SC3 in `eval/results/sc3_report.json` (Syft-enabled coverage gap, +154 over cdxgen+syft 5070, Δ=3 %).
- **`tracks` interval semantics** — `interval_hours` default 24, range 1..720. Failed scans still bump `last_check_at` so a broken target waits a full interval before retry.
- **`update_cadence_days` is consumed ONLY in SSVC impact**, never in the weighted formula — design decision to avoid double-counting (see `notes/priority.md` §"Why update_cadence_days appears only in SSVC impact").

### Historical notes
- `core/ot_layer/` does not exist — it was renamed to `core/extended_coverage/` on 2026-04-23. Old git commits and some external notes still reference the old name.
- `notes/` was consolidated on 2026-04-24 — originals (future.txt, growth.txt, signature.txt, parsing.txt, …) are gone; current thematic files carry the content. `notes/thesis.md` was retired in favour of the Overleaf-managed thesis.

---

## 6. How to extend

- **Add a new detector** → write a function in `core/extended_coverage/` returning `list[OTComponent]`; register it in `detectors._COMPONENT_DETECTORS`. (Don't repeat the `plc_scada` mistake — register it.)
- **Add a new vuln source** → add a phase function in `core/vuln_checker.py`, plug it into `scan()`.
- **Add a new PURL category** → entry in `_PURL_MAP` (`core/extended_coverage/models.py`); add routing in `vuln_checker.py` if not OSV/NVD.
- **Add a new noise filter** → drop a module in `core/noise_filter/`, export it from `__init__.py`, call it from `core/pipeline.py` step 4b/4c.
- **Add a call rule** → extend `_CALL_RULES` in `core/noise_filter/call_verifier.py`.
- **Add a context-profile preset** → entry in `core/priority/profiles.PRESETS`; the dashboard picks it up automatically via `/api/priority/presets`.
- **Add a CSAF feed** → subclass with `list_documents()` in `core/csaf/feeds.py`; register in `FEEDS`. Records flow through the same parser/storage.
- **Tune priority weights** → re-run `eval/tune_weights.py`. Adopt only if `Δρ_test ≥ 0.05` (acceptance criterion in `notes/priority.md`).
