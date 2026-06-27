# SBOM-Shield

SBOM-based vulnerability scanner with OT/ICS support, built for small and mid-size companies that write their own industrial software.

SBOM-Shield combines [cdxgen](https://github.com/CycloneDX/cdxgen) (primary SBOM generator, deeper coverage of C/C++ build systems and language manifests) with [Syft](https://github.com/anchore/syft) as a secondary scanner that fills gaps cdxgen leaves (OS packages, certain binary metadata). On top of the merged SBOM, a custom **extended-coverage** layer detects implicit industrial dependencies — protocol libraries, RTOS kernels, PLC runtime references, vendor BSP/HAL layers, device description files, and Conan packages — that conventional SCA tools miss entirely. Findings are then ranked using an **SSVC-style prioritisation framework** that takes the deployment context (Purdue level, network exposure, patchability) into account.

---

## How it works

```
target directory
    │
    ├─ cdxgen ─────────────── CycloneDX JSON (primary, manifest-aware)
    ├─ Syft (fill-in) ─────── CycloneDX JSON (gaps cdxgen missed)
    │     └─ merge ────────── cdxgen wins on conflict; per-component source kept
    │                              │
    ├─ Manifest parsers ───── requirements.txt / package.json / conanfile / conan_*.txt
    │                              │
    ├─ extended_coverage ──── implicit OT/ICS dependencies
    │   ├─ Protocol detector       (Modbus, OPC UA, DNP3, BACnet, MQTT, …)
    │   ├─ RTOS detector           (FreeRTOS, Zephyr, RIOT, NuttX, Mbed, …)
    │   ├─ BSP/HAL detector        (STM32 HAL, ESP-IDF, Nordic SDK, Pico SDK, …)
    │   ├─ PLC/SCADA detector      (CODESYS, TwinCAT, OpenPLC, 4diac, ST libs, …)
    │   ├─ Device desc detector    (EDS, GSDML, ESI, IODD, FDT/DTM)
    │   ├─ Build manifest detector (.gitmodules, CMake FetchContent)
    │   └─ ELF detector            (versioned strings in shipped binaries)
    │                              │
    │                     merged component list
    │                              │
    ├─ noise_filter ──────── reachability tag (direct vs lock-file-only) +
    │                        tree-sitter call-site verification (C/C++)
    │                              │
    ├─ Vuln scan ─────────── OSV + NVD (with CPE version-range filtering) +
    │                        CISA KEV + EPSS + VulDB (optional, ICS/SCADA)
    │                              │
    ├─ CSAF enrichment ───── vendor PSIRT advisories (Siemens, Schneider, …)
    │                              │
    ├─ priority (SSVC) ───── Act / Attend / Track* / Track buckets,
    │                        intra-bucket score from context profile
    │                              │
    └─ Report ────────────── JSON + console + SQLite + dashboard
```

---

## Requirements

- **Python 3.10+**
- **[cdxgen](https://github.com/CycloneDX/cdxgen)** — installed and in `PATH` (primary SBOM tool)
- **[Syft](https://github.com/anchore/syft)** — optional, in `PATH` (secondary fill-in; pipeline runs without it via `--no-syft-fallback`)
- **Node.js 20+** — required by cdxgen
- **git** — used by the build-manifest detector for submodule version extraction (optional; degrades gracefully if absent)

Install cdxgen:
```bash
npm install -g @cyclonedx/cdxgen
```

Install Syft (recommended for full coverage):
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

Verify:
```bash
cdxgen --version
syft version
```

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/maPiras/SBOM-Shield.git
cd SBOM-Shield

# 2. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install Python dependencies
pip install -r requirements.txt
```

---

## First-time setup

### 1. Configure environment variables (optional for local use)

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `SBOMSHIELD_SECRET` | `sbomshield-dev-secret-change-in-prod` | JWT signing secret — change this in production |
| `SBOMSHIELD_REPOS_DIR` | `~/repos` | Absolute path to the folder containing projects available for scanning through the dashboard |
| `VULDB_API_KEY` | _unset_ | If set, enables VulDB enrichment (ICS/SCADA-focused CVE source). Get a free key at [vuldb.com](https://vuldb.com/?userinfo.api) |

### 2. Initialise the database and create default users

```bash
python storage/seed_db.py
```

This creates the SQLite database at `storage/scans.db`, applies the schema, and inserts two default accounts:

| Email | Password | Role |
|-------|----------|------|
| `admin@sbom-shield.local` | `admin1234` | Admin |
| `user@sbom-shield.local` | `user1234` | User |

Change these credentials before any shared or production deployment.

To import existing scan reports into the database at the same time:
```bash
python storage/seed_db.py --reports-dir ./reports
```

---

## Running the dashboard (API server)

```bash
uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
```

The server starts on **http://localhost:8000**.

- `--host 0.0.0.0` makes it reachable from other machines on the network. Use `127.0.0.1` for local-only access.
- `--reload` enables hot-reload on code changes (development mode; omit in production).

### Accessing the dashboard

1. Open **http://localhost:8000** in a browser.
2. Click **Access Platform** — a login modal appears.
3. Enter your credentials (default: `admin@sbom-shield.local` / `admin1234`).
4. After login you are redirected to **http://localhost:8000/dashboard/user.html**.

### Dashboard features

**Overview panel** — total scans, active projects, open vulnerabilities, and CISA KEV matches across all stored scans.

**Run a new scan** — pick a repository from the dropdown (populated from `SBOMSHIELD_REPOS_DIR`), choose a **context profile** for SSVC prioritisation, toggle the **extended-coverage** switch to include or skip OT/ICS static analysis, and click **Run Scan**. Progress streams in real time via Server-Sent Events.

**Tracks (continuous monitoring)** — promote any scan to a **track** to have SBOM-Shield re-run the pipeline periodically (configurable interval) against the same project. When the upstream version changes, use **Upgrade** to pin the new version while keeping the full historical timeline. Useful for surfacing newly disclosed CVEs in dependencies you have already vetted.

**Scan history** — paginated table of all past scans with verdict (PASS / WARN / FAIL), component count, vuln count, and KEV matches. Click any row to expand its full vulnerability report.

**Scan detail view**
- Vulnerable components with per-CVE CVSS score, EPSS probability, fix version, KEV flag, CSAF advisory link, and source (OSV / NVD / CISA-KEV / VulDB).
- **Priority view**: components grouped by SSVC bucket (Act / Attend / Track* / Track) with the context profile applied.
- **Extended-coverage section**: components found by the OT detector (protocol libraries, RTOS, BSP, PLC runtimes) with detection evidence and confidence.
- **Detected-but-unanalyzed components** (device description files, unknown vendor libraries that have no queryable PURL).
- **Indirect components**: lock-file-only / non-imported components, suppressed from the main vuln view by default.
- Full SBOM component list.

**Charts** — severity breakdown, vulnerability trend over time, source distribution (OSV / NVD / CISA-KEV / VulDB), and active KEV matches ranked by CVSS.

### Adding repositories to scan

Place (or clone) projects into the `repos/` directory (or whatever `SBOMSHIELD_REPOS_DIR` points to):

```bash
cd repos/
git clone https://github.com/your-org/your-project
```

The dashboard dropdown lists every subdirectory of `SBOMSHIELD_REPOS_DIR` automatically. Demo repositories are included under `repos/`:

| Directory | What it tests |
|-----------|---------------|
| `repos/case2_embedded/` | Embedded C/C++ gateway — libmodbus, lwIP, mbedTLS, FreeRTOS+TCP |
| `repos/case_plc/` | CODESYS / 4diac PLC project — CODESYS runtime, OSCAT BASIC |
| `repos/OpenPLC_v3/` | Full OpenPLC runtime source |

---

## CLI usage

The CLI runs a complete scan without needing the API server and writes results to disk. If the API server is running, the CLI also forwards the report to it so results appear in the dashboard.

```bash
# Activate the virtualenv first
source .venv/bin/activate

# Basic scan — writes sbom.json and security_report.json to ./reports/
python3 main.py ./path/to/project

# Use a pre-generated SBOM file (skips both cdxgen and Syft)
python3 main.py ./project --sbom-file ./sbom.json

# Write output to a specific directory
python3 main.py ./project --output-dir /tmp/scan-results

# Fail only on CRITICAL (default threshold is HIGH)
python3 main.py ./project --fail-on CRITICAL

# Disable the extended-coverage layer (plain IT-only scan)
python3 main.py ./project --no-extended-coverage

# Include CVEs from transitive / lock-file-only dependencies
# (off by default — reachability filter suppresses them as noise)
python3 main.py ./project --include-indirect

# Apply a specific SSVC context profile (default: production_ot)
python3 main.py ./project --context-profile safety_critical_ot

# Pass a custom profile inline as JSON
python3 main.py ./project --context-profile '{"purdue_level":1,"safety_critical":true,"network_zone":"isolated","patchable":false}'

# Skip the Syft fill-in (cdxgen-only — faster, less coverage)
python3 main.py ./project --no-syft-fallback

# Allow cdxgen to perform online dependency resolution (default: offline)
python3 main.py ./project --online-resolution

# Verbose debug logging
python3 main.py ./project -v
```

### Context profiles (SSVC prioritisation)

| Preset | Intended use |
|--------|--------------|
| `production_ot` (default) | OT controller in a production plant; safety not life-critical, mostly isolated network |
| `safety_critical_ot` | Safety-instrumented system (SIS) or comparable life-critical OT |
| `lab_research` | Development bench / R&D — patchable, network-isolated, no safety impact |
| `automotive_infotainment` | In-vehicle infotainment / non-safety automotive ECU |

Each preset feeds the SSVC decision tree (exploitation × utility × technical impact × mission-and-well-being impact) and the intra-bucket score. Pass `--context-profile <JSON>` to override any preset field for a single run.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No vulnerabilities at or above the `--fail-on` threshold |
| `1` | At least one vulnerability at or above the threshold |
| `2` | Fatal error — directory not found, SBOM generation failure, or parse failure |

### CI/CD integration example (GitHub Actions)

```yaml
- name: Run SBOM-Shield scan
  run: |
    source .venv/bin/activate
    python3 main.py ${{ github.workspace }} --fail-on HIGH --context-profile production_ot
```

The non-zero exit on findings causes the step to fail, gating the pipeline.

---

## Output files

Every scan produces two files under `--output-dir` (default `./reports/`):

| File | Contents |
|------|----------|
| `sbom.json` | Merged CycloneDX JSON SBOM (cdxgen + Syft fill-in) |
| `security_report.json` | Full report: vulnerable components, all CVEs with CVSS/EPSS/KEV, extended-coverage results, SSVC priority buckets, indirect-component list |

The report is also persisted to `storage/scans.db` (SQLite) for the dashboard.

---

## Project structure

```
SBOM-Shield/
├── main.py                          CLI entry point and pipeline orchestrator
│
├── core/
│   ├── pipeline.py                  Library entry point used by the API server
│   ├── cdxgen_runner.py             Invokes cdxgen and returns CycloneDX JSON
│   ├── syft_runner.py               Invokes Syft (secondary scanner)
│   ├── sbom_merger.py               Merges cdxgen + Syft outputs (cdxgen wins)
│   ├── sbom_generator.py            High-level "generate or load" facade
│   ├── sbom_parser.py               Extracts Component objects from CycloneDX
│   ├── requirements_parser.py       Injects constrained deps (>= / ~=) the SBOM tools missed
│   ├── vuln_checker.py              OSV + NVD + KEV queries, CPE version-range filtering
│   ├── vuldb_checker.py             VulDB enrichment (optional, ICS/SCADA)
│   ├── epss_checker.py              EPSS exploit-probability scoring
│   ├── report_generator.py          JSON report builder and console output
│   ├── tracking.py                  Periodic re-scan scheduler for "tracks"
│   │
│   ├── extended_coverage/           OT/ICS static analysis layer
│   │   ├── detectors.py             Orchestrator — runs sub-detectors concurrently
│   │   ├── scanners.py              Protocol / RTOS / BSP / PLC / device-desc rules
│   │   ├── build_detectors.py       .gitmodules + CMake FetchContent
│   │   ├── elf_detector.py          Versioned strings in shipped ELF binaries
│   │   ├── conan_parser.py          Conan package manifests (conanfile.*, conan_*.txt)
│   │   ├── version_extractor.py     Vendored-header version extraction
│   │   └── models.py                Data models, PURL mapping, SBOM enrichment
│   │
│   ├── noise_filter/                Reduces false positives
│   │   ├── reachability.py          Tags components as direct vs lock-file-only
│   │   └── call_verifier.py         tree-sitter AST call-site verification (C/C++)
│   │
│   ├── priority/                    SSVC-style prioritisation
│   │   ├── ssvc.py                  SSVC decision tree (Act / Attend / Track* / Track)
│   │   ├── scoring.py               Intra-bucket score from context profile
│   │   ├── profiles.py              Context-profile presets and YAML loader
│   │   └── models.py                ContextProfile / PriorityResult dataclasses
│   │
│   └── csaf/                        Vendor PSIRT (CSAF 2.0) ingestion
│       ├── feeds.py                 Siemens / Schneider / vendor feed fetchers
│       ├── parser.py                CSAF 2.0 → internal model
│       └── storage.py               SQLite cache (csaf_advisories table)
│
├── api/
│   └── server.py                    FastAPI server — REST + SSE scan streaming + tracks + static hosting
│
├── storage/
│   ├── database.py                  SQLite schema, read/write helpers (scans, tracks, users)
│   ├── seed_db.py                   Database initialiser and default user seeder
│   └── scans.db                     SQLite database (created on first run; not in git)
│
├── dashboard/
│   └── public/
│       ├── index.html               Landing page with login modal
│       ├── dashboard/user.html      Main dashboard (requires login)
│       ├── main.js                  Landing page JavaScript (login flow)
│       └── style.css                Shared stylesheet
│
├── eval/                            Benchmark and evaluation scripts (thesis)
├── notes/                           Design notes and session logs
├── reports/                         Scan output directory (created on first run)
├── repos/                           Default location for projects to scan
├── requirements.txt                 Python dependencies
└── .env.example                     Environment variable template
```

---

## Detection coverage

**Protocol libraries**
libmodbus, pymodbus, modbus-tk, jsmodbus, modbus-serial, open62541, asyncua, node-opcua, opcua, opendnp3, pydnp3, libiec61850, bacpypes, bacpypes3, BAC0, CANopen, python-can, pycomm3, ethernet-ip, cpppo, SOEM (EtherCAT), lely-core, Snap7, paho-mqtt, mosquitto, lwIP, mbedTLS, FreeRTOS+TCP

**RTOS / embedded runtimes**
FreeRTOS, Zephyr, RIOT, NuttX, Mbed OS, ThreadX, Contiki-NG, ESP-IDF, Arduino, PlatformIO, Pico SDK, OpenPLC, matiec, 4diac FORTE, CODESYS

**BSP / HAL layers**
STM32 CubeMX, ESP-IDF, TI DriverLib, NXP MCUXpresso, Nordic nRF SDK, Pico SDK

**PLC / SCADA IDE projects**
CODESYS project files (`.project`, `.solution`), TwinCAT (`.tsproj`, `.tmc`), 4diac (`.fbt`), STEP 7 / TIA Portal, Studio 5000 / RSLogix, IEC 61131-3 Structured Text (`.st`, `.iec`), PLCopen XML library references, OSCAT BASIC / NETWORK / Building, Beckhoff Tc2_*/Tc3_* libraries

**Device description files** (audit/inventory — no vulnerability scan)
CANopen / DeviceNet EDS, PROFINET GSDML/GSD, EtherCAT ESI, IO-Link IODD, FDT/DTM

**Package managers**
pip / pyproject (cdxgen + manifest fallback), npm (cdxgen), **Conan** (`conanfile.txt`, `conanfile.py`, `conan_*.txt`, `.lock.host`, `.lock.cross`)

**Build manifests**
`.gitmodules` (submodule URL mapping + version extraction from vendored directories), CMake `FetchContent_Declare` / `ExternalProject_Add`

**Binary fallback**
ELF version-string extraction for libraries shipped without source

---

## Vulnerability sources

| Source | What it covers |
|--------|---------------|
| **OSV** | Open-source Python, Node.js, Go and other ecosystem packages — exact version matching |
| **NVD** | C/C++ open-source libraries (`pkg:github/`) and PLC runtime vendor components (`pkg:generic/`) — keyword search with CPE version-range filtering |
| **CISA KEV** | Known-Exploited Vulnerabilities catalogue — cross-referenced against all findings |
| **EPSS** | Exploit-probability score for each CVE |
| **VulDB** (optional) | ICS/SCADA-focused source covering CVEs and exploit availability beyond NVD; requires `VULDB_API_KEY` |
| **CSAF** | Vendor PSIRT advisories (Siemens, Schneider, …) attached to matching CVEs |

---

## Prioritisation (SSVC)

Every finding is placed in one of four SSVC decision buckets:

| Bucket | Meaning |
|--------|---------|
| **Act** | Patch / mitigate immediately. Active exploitation, automatable, critical impact. |
| **Attend** | Schedule promptly. High impact and/or proof-of-concept exploit. |
| **Track\*** | Watch closely. Borderline cases worth a re-review. |
| **Track** | Routine. Low priority; record and revisit on next cycle. |

The bucket is driven by the SSVC decision tree (Exploitation × Utility × Technical Impact × Mission & Well-being Impact), with inputs coming from the CVE record (KEV flag, EPSS, CVSS) and from the **context profile** (Purdue level, safety-critical flag, network zone, patchability). Within a bucket, components are ordered by an intra-bucket numerical score so the dashboard always presents a deterministic action list.

---

## Troubleshooting

**`cdxgen: command not found`** — install via `npm install -g @cyclonedx/cdxgen`. Requires Node.js 20+.

**`syft: command not found`** — make sure Syft is installed and on `PATH`, or pass `--no-syft-fallback` to skip it.

**`No module named 'fastapi'`** — the virtual environment is not activated. Run `source .venv/bin/activate` before starting the server or CLI.

**Login fails with "Invalid credentials"** — the database has not been seeded. Run `python storage/seed_db.py` first.

**Dashboard shows no scan history** — either no scans have been run yet, or the CLI ran without the API server being up (the report was saved to disk but not forwarded). Import existing reports with:
```bash
python storage/seed_db.py --reports-dir ./reports
```

**NVD requests are slow or return 429 errors** — NVD rate-limits unauthenticated requests to ~5 per 30 seconds. For faster scans, obtain a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key (env-var wiring is on the roadmap).

**Extended-coverage finds nothing** — if the project has no OT/ICS content, this is expected. For a project that should have detections, try `-v` to see per-detector log output, or call the OT-only API endpoint:
```bash
curl -s -X POST http://localhost:8000/api/ot/analyze \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/absolute/path/to/project"}'
```

**Too few CVEs reported** — reachability filtering hides CVEs in lock-file-only / non-imported components by default. Re-run with `--include-indirect` to surface them.
