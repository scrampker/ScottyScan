# ScottyScan Platform Architecture Spec

## Project Overview

ScottyScan is a modular vulnerability scanning platform that wraps multiple open-source scanning engines behind a unified orchestration layer. Each engine is a **toggleable module** that can be enabled/disabled via a configuration UI, updated independently from upstream sources, and produces normalized output consumable by a single reporting pipeline.

---

## Core Architecture

### Plugin Adapter Pattern

Each scanning engine is wrapped in a **plugin adapter** that implements a common interface. The orchestrator communicates with engines exclusively through this interface — never directly.

```
┌─────────────────────────────────────────────────┐
│                  ScottyScan Core                  │
│                                                  │
│  ┌───────────┐  ┌───────────┐  ┌─────────────┐  │
│  │ Scheduler │  │ Normalizer│  │  Report Gen  │  │
│  └─────┬─────┘  └─────┬─────┘  └──────┬──────┘  │
│        │              │               │          │
│  ┌─────▼──────────────▼───────────────▼──────┐   │
│  │           Plugin Orchestrator              │   │
│  └─────┬──────┬──────┬──────┬──────┬─────────┘   │
│        │      │      │      │      │             │
│  ┌─────▼┐ ┌──▼───┐ ┌▼────┐ ┌▼───┐ ┌▼─────┐     │
│  │OpenVAS│ │Nuclei│ │Nmap │ │Vuls│ │Custom│     │
│  │Adapter│ │Adapt.│ │NSE  │ │Ad. │ │Plugin│     │
│  └──┬───┘ └──┬───┘ └┬────┘ └┬───┘ └┬─────┘     │
└─────┼────────┼──────┼───────┼──────┼────────────┘
      │        │      │       │      │
      ▼        ▼      ▼       ▼      ▼
  [OpenVAS] [Nuclei] [Nmap] [Vuls] [Future]
```

### Common Plugin Interface

Every plugin adapter MUST implement these methods:

```
interface ScannerPlugin {
    // Identity & metadata
    name: string
    version: string
    description: string
    capabilities: string[]          // e.g., ["network", "web", "authenticated", "cve-detection"]
    
    // Lifecycle
    initialize(): Result            // Install/verify dependencies
    healthCheck(): HealthStatus     // Is the engine available and functional?
    shutdown(): Result              // Graceful cleanup
    
    // Configuration
    getConfig(): PluginConfig       // Current engine-specific settings
    setConfig(config): Result       // Apply engine-specific settings
    isEnabled(): bool               // Toggle state
    enable(): Result
    disable(): Result
    
    // Update management
    checkForUpdates(): UpdateInfo   // Check upstream for new feeds/templates/packages
    applyUpdate(): UpdateResult     // Pull and apply updates
    getUpdateHistory(): UpdateLog[] // Audit trail of applied updates
    getCurrentFeedVersion(): string // Current signature/template version
    
    // Scanning
    scan(target: ScanTarget, profile: ScanProfile): ScanJob
    getScanStatus(jobId): ScanStatus
    cancelScan(jobId): Result
    getScanResults(jobId): NormalizedResults  // MUST return normalized format
    
    // Raw access (optional, for advanced users)
    getRawResults(jobId): RawEngineOutput
}
```

---

## Plugin Specifications

### 1. OpenVAS / Greenbone (GVM)

**Purpose:** Deep authenticated vulnerability scanning with NASL plugin library.

**Integration method:**
- Wrap `ospd-openvas` daemon via OSP (Open Scanner Protocol) — XML over Unix socket or TCP
- Alternatively, communicate with `gvmd` via GMP (Greenbone Management Protocol) for higher-level task management
- Feed updates via `greenbone-feed-sync` CLI tool

**Installation requirements:**
- `ospd-openvas`, `openvas-scanner`, `gvmd`, `gvm-libs`, `pg-gvm` (PostgreSQL extension)
- Redis for scanner KB cache
- PostgreSQL for gvmd backend
- Community Feed (NVT, SCAP, CERT data)

**Update mechanism:**
- `greenbone-feed-sync --type nasl` — sync NVT (NASL vulnerability test) feed
- `greenbone-feed-sync --type scap` — sync SCAP/CVE data
- `greenbone-feed-sync --type cert` — sync CERT advisories
- Schedule via cron or trigger from UI. Feed is GPLv2 licensed.

**Adapter responsibilities:**
- Manage GVM service lifecycle (start/stop `ospd-openvas`, `gvmd`, Redis)
- Translate ScottyScan scan profiles into GVM scan configs
- Map GVM task states to ScottyScan job states
- Parse GVM XML results into normalized format
- Handle GVM authentication (admin user management)

**Key config options exposed:**
- Scan config (Full and Fast, Full and Deep, custom)
- Credential sets for authenticated scanning
- Port lists
- Concurrent scan limits
- Feed sync schedule

---

### 2. Nuclei (ProjectDiscovery)

**Purpose:** Template-based scanning for CVEs, misconfigs, exposures, tech detection. Fast, broad coverage.

**Integration method:**
- Invoke `nuclei` CLI as a subprocess with JSON output (`-jsonl` flag)
- OR embed as a Go library if ScottyScan core is Go-based
- Template library is a separate Git repo (`nuclei-templates`)

**Installation requirements:**
- Single Go binary — `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
- Or download prebuilt release binary
- Templates: `nuclei -update-templates` or `git clone github.com/projectdiscovery/nuclei-templates`

**Update mechanism:**
- `nuclei -update` — update the Nuclei binary itself
- `nuclei -update-templates` — pull latest community templates
- Git-based: `git -C /path/to/nuclei-templates pull`
- Custom templates can coexist in a separate directory

**Adapter responsibilities:**
- Manage template directory and custom template overlays
- Translate scan profiles to Nuclei tag/severity filters (e.g., `-severity critical,high -tags cve`)
- Parse JSONL output stream into normalized results
- Support rate-limiting and concurrency configuration
- Track template version (git commit hash or release tag)

**Key config options exposed:**
- Template tags filter (cve, misconfig, exposure, tech, etc.)
- Severity filter (info, low, medium, high, critical)
- Rate limiting (requests/sec, concurrent templates)
- Custom template directories
- Interactsh (OOB testing) toggle
- Headless browser mode toggle
- Proxy settings

---

### 3. Nmap + NSE (Nmap Scripting Engine)

**Purpose:** Network discovery, port scanning, service fingerprinting, and targeted vulnerability checks via NSE scripts.

**Integration method:**
- Invoke `nmap` CLI with XML output (`-oX`)
- Use NSE categories: `vuln`, `exploit`, `auth`, `default`
- Supplement with `vulscan` and `vulners` NSE scripts for CVE correlation

**Installation requirements:**
- `nmap` package (most distros)
- Additional NSE scripts: `vulscan` (manual install to `/usr/share/nmap/scripts/`)
- `vulners` NSE script (included in recent Nmap versions)
- `vulscan` databases: CSV files mapping service banners to CVEs

**Update mechanism:**
- OS package manager for Nmap itself (`apt update && apt upgrade nmap`)
- `nmap --script-updatedb` — rebuild script database after adding scripts
- `vulscan` DB update: download updated CSVs from upstream repo
- `vulners` uses the Vulners.com API at scan time (live lookups)

**Adapter responsibilities:**
- Translate scan profiles to Nmap flags and NSE script selections
- Parse Nmap XML output into normalized format
- Merge NSE script output (especially `vulners` and `vulscan` CVE matches) into findings
- Handle privileged execution (raw socket scans require root/cap_net_raw)
- Manage scan timing templates (-T0 through -T5)

**Key config options exposed:**
- Port range (top-100, top-1000, all, custom)
- Scan type (SYN, TCP connect, UDP, etc.)
- Timing template (T0-T5)
- NSE script categories and individual scripts
- OS detection toggle
- Service version detection intensity
- Host discovery method

---

### 4. Vuls

**Purpose:** Agentless vulnerability scanning for Linux/FreeBSD hosts via SSH. Strong for patch-level CVE detection.

**Integration method:**
- Invoke `vuls` CLI (Go binary) — `vuls scan`, `vuls report`
- Config-file driven (`config.toml`)
- JSON report output

**Installation requirements:**
- `vuls` binary
- `go-cve-dictionary` — NVD/JVN CVE database fetcher
- `goval-dictionary` — OVAL definition fetcher
- `gost` — security tracker data (Debian, Ubuntu, RedHat, Microsoft)
- `go-exploitdb` — exploit-db cross-reference
- `go-kev` — CISA KEV data
- SQLite or MySQL for local vulnerability databases

**Update mechanism:**
- `go-cve-dictionary fetch nvd` — update NVD data
- `goval-dictionary fetch ubuntu/debian/redhat` — update OVAL definitions
- `gost fetch debian/ubuntu/redhat` — update security tracker
- `go-exploitdb fetch exploitdb` — update exploit DB
- `go-kev fetch` — update CISA KEV
- Schedule all fetchers on a daily cron or trigger from UI

**Adapter responsibilities:**
- Generate `config.toml` dynamically from ScottyScan target definitions
- Manage SSH credential/key mappings
- Orchestrate the multi-step fetch → scan → report pipeline
- Parse JSON reports into normalized format
- Handle the multiple database update commands as a single "update" operation

**Key config options exposed:**
- SSH credentials per host/group
- Scan mode (fast-root, deep, offline)
- CVE database sources to include
- OVAL definition distros to fetch
- Report format and verbosity

---

### 5. Custom Plugin (Extensibility Framework)

**Purpose:** Allow users (Steven and future contributors) to create new plugins without modifying ScottyScan core.

**Plugin discovery:**
- Plugins live in a designated directory (e.g., `~/.scottyscan/plugins/`)
- Each plugin is a directory containing a manifest file (`plugin.yaml`) and an executable or script
- ScottyScan scans the plugin directory at startup and registers valid plugins

**Manifest format (`plugin.yaml`):**
```yaml
name: "my-custom-scanner"
version: "1.0.0"
description: "Custom scanner for XYZ"
author: "Steven"
capabilities:
  - network
  - cve-detection
engine:
  type: executable          # executable | python | powershell | go
  entrypoint: "./scanner"   # relative to plugin directory
  args_format: "json"       # how ScottyScan passes scan config: json | cli-flags | env
  output_format: "jsonl"    # expected output format: jsonl | xml | csv
update:
  method: git               # git | script | manual
  repo: "https://github.com/user/my-scanner"
  branch: "main"
  post_update: "./setup.sh" # optional post-update hook
```

---

## Normalized Output Schema

All plugins MUST emit results conforming to this schema. The normalizer in ScottyScan core validates and enriches.

```json
{
    "finding_id": "uuid-v4",
    "source_engine": "nuclei",
    "source_template_id": "CVE-2025-15556",
    "timestamp": "2026-02-06T14:30:00Z",
    
    "target": {
        "host": "192.168.1.50",
        "port": 443,
        "protocol": "tcp",
        "service": "https",
        "hostname": "webserver01.corp.local"
    },
    
    "vulnerability": {
        "id": "CVE-2025-15556",
        "title": "Notepad++ Supply Chain RCE",
        "description": "...",
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-494",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-15556"
        ]
    },
    
    "evidence": {
        "raw_output": "...",
        "matched_at": "https://192.168.1.50:443/path",
        "matcher_name": "version-check",
        "extracted_data": {}
    },
    
    "remediation": {
        "description": "Update Notepad++ to version X.Y.Z or later",
        "effort": "low",
        "references": []
    },
    
    "metadata": {
        "scan_job_id": "uuid-v4",
        "scan_profile": "full-and-fast",
        "engine_version": "3.1.0",
        "feed_version": "2026-02-06",
        "confidence": "high"
    }
}
```

---

## Configuration & Toggle System

### Global Config (`scottyscan.yaml`)

```yaml
scottyscan:
  data_dir: "~/.scottyscan"
  log_level: "info"
  report_output_dir: "./reports"
  
  plugins:
    openvas:
      enabled: true
      auto_update: true
      update_schedule: "0 2 * * *"       # daily at 2 AM
      config:
        default_scan_profile: "full-and-fast"
        max_concurrent_scans: 2
        
    nuclei:
      enabled: true
      auto_update: true
      update_schedule: "0 3 * * *"
      config:
        severity_filter: ["critical", "high", "medium"]
        rate_limit: 150
        template_tags: ["cve", "misconfig"]
        custom_templates_dir: "~/.scottyscan/nuclei-custom/"
        
    nmap:
      enabled: true
      auto_update: false                   # manual updates preferred
      config:
        default_port_range: "top-1000"
        timing_template: "T4"
        nse_categories: ["vuln", "auth"]
        
    vuls:
      enabled: false                       # disabled by default
      auto_update: true
      update_schedule: "0 4 * * *"
      config:
        scan_mode: "fast-root"
        
    custom_plugins_dir: "~/.scottyscan/plugins/"
```

### Toggle API

Plugins can be toggled at runtime via CLI or (future) web UI:

```bash
scottyscan plugin enable nuclei
scottyscan plugin disable openvas
scottyscan plugin list                    # show all plugins and status
scottyscan plugin status nuclei           # detailed health + version info
scottyscan plugin update nuclei           # trigger manual update
scottyscan plugin update --all            # update all enabled plugins
```

---

## Update Management System

### Update Pipeline

```
                    ┌──────────────┐
                    │  Scheduler   │
                    │  (cron-like) │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ Update Check │◄── Manual trigger (CLI/UI)
                    │  per plugin  │
                    └──────┬───────┘
                           │
              ┌────────────▼────────────┐
              │   Plugin-specific       │
              │   update commands       │
              │                         │
              │  OpenVAS: feed-sync     │
              │  Nuclei:  git pull      │
              │  Nmap:    pkg + scriptdb│
              │  Vuls:    multi-fetch   │
              │  Custom:  git/script    │
              └────────────┬────────────┘
                           │
                    ┌──────▼───────┐
                    │  Validation  │
                    │  & health    │
                    │  check       │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  Log result  │
                    │  & notify    │
                    └──────────────┘
```

### Update Audit Log

Every update is logged:

```json
{
    "plugin": "nuclei",
    "timestamp": "2026-02-06T03:00:00Z",
    "action": "template_update",
    "previous_version": "v10.1.0",
    "new_version": "v10.1.1",
    "templates_added": 47,
    "templates_modified": 12,
    "status": "success",
    "triggered_by": "scheduled"
}
```

---

## Scan Orchestration

### Scan Profiles

Predefined profiles that map to engine-specific configurations:

| Profile | OpenVAS | Nuclei | Nmap | Vuls |
|---------|---------|--------|------|------|
| **Quick Discovery** | — | tags: tech | Top 100 ports, -T4 | — |
| **Standard** | Full and Fast | severity: med+ | Top 1000, version detect | fast |
| **Deep** | Full and Deep | all templates | All ports, all NSE vuln | deep |
| **Compliance** | Policy audit | misconfig tags | auth scripts | fast-root |
| **Custom** | User-defined | User-defined | User-defined | User-defined |

### Scan Execution Flow

```
1. User defines target(s) and selects profile
2. Orchestrator checks which plugins are ENABLED
3. For each enabled plugin:
   a. Translate profile to engine-specific config
   b. Submit scan job via adapter
   c. Monitor job status (poll or callback)
4. As results arrive, normalize via adapter
5. Deduplicate findings across engines (same CVE + same host = merge)
6. Enrich with cross-references (CISA KEV, EPSS, exploit-db)
7. Generate unified report
```

### Finding Deduplication

When multiple engines detect the same vulnerability on the same target:

- Match on: CVE ID + target host + target port
- Merge strategy: keep highest confidence, union of evidence, note all source engines
- Flag "corroborated" findings (detected by 2+ engines) for higher confidence scoring

---

## Reporting

### Output Formats

- **JSON** — machine-readable, full detail
- **CSV** — flat export for Excel analysis (matches Steven's existing workflow)
- **Markdown** — human-readable summary
- **PDF** — formal report for customer handoff / CAB documentation
- **HTML** — interactive dashboard (future)

### Report Sections

1. **Executive Summary** — total findings by severity, engines used, scan duration
2. **Finding Details** — grouped by host, then severity. Each finding includes: CVE, description, evidence, remediation, source engine(s), corroboration status
3. **Engine Coverage Matrix** — which engines scanned which targets, any errors
4. **Update Status** — feed/template versions at time of scan
5. **Appendix: Raw Engine Outputs** — optional, for deep-dive troubleshooting

---

## Technology Recommendations

### Primary Language Options

| Option | Pros | Cons |
|--------|------|------|
| **Python** | Rich library ecosystem, easy subprocess management, familiar scripting | Performance for large-scale parallel scanning |
| **Go** | Native Nuclei integration, single binary distribution, excellent concurrency | Steeper learning curve, less rapid prototyping |
| **Hybrid (Python orchestrator + Go plugins)** | Best of both worlds | Build complexity |

**Recommendation:** Start with **Python** for the orchestrator and adapter layer. It aligns with Steven's existing scripting workflow, has excellent subprocess/process management, and libraries for XML/JSON parsing. If performance becomes an issue, individual hot paths can be rewritten in Go.

### Key Dependencies

- **Python 3.11+**
- `asyncio` / `aiohttp` — async scan job management
- `pydantic` — config and result schema validation
- `click` or `typer` — CLI framework
- `rich` — terminal UI for status/progress
- `pyyaml` — config parsing
- `jinja2` — report template rendering
- `schedule` or `APScheduler` — update scheduling
- Docker (optional) — containerize engine dependencies (especially OpenVAS/GVM)

---

## Directory Structure

```
scottyscan/
├── scottyscan/
│   ├── __init__.py
│   ├── cli.py                      # CLI entrypoint
│   ├── config.py                   # Config loading and validation
│   ├── orchestrator.py             # Scan orchestration engine
│   ├── normalizer.py               # Result normalization and dedup
│   ├── reporter.py                 # Report generation
│   ├── scheduler.py                # Update and scan scheduling
│   ├── models/
│   │   ├── finding.py              # Normalized finding schema
│   │   ├── scan_job.py             # Scan job model
│   │   └── plugin.py               # Plugin interface / base class
│   ├── plugins/
│   │   ├── base.py                 # Abstract base plugin class
│   │   ├── openvas_adapter.py
│   │   ├── nuclei_adapter.py
│   │   ├── nmap_adapter.py
│   │   ├── vuls_adapter.py
│   │   └── custom_loader.py        # Dynamic plugin discovery
│   └── utils/
│       ├── feed_sync.py            # Update management
│       ├── dedup.py                # Finding deduplication
│       └── enrichment.py           # CVE enrichment (KEV, EPSS)
├── templates/
│   ├── report_pdf.html
│   ├── report_md.jinja2
│   └── report_csv.jinja2
├── tests/
├── scottyscan.yaml                  # Default config
├── pyproject.toml
└── README.md
```

---

## ScottyScan as the Core Engine

ScottyScan is not just another plugin -- it is the **enrichment backbone** of ScottyScan. External engines (OpenVAS, Nuclei, Nmap, Vuls) detect vulnerabilities against IP:port targets. ScottyScan provides the context that makes those findings actionable.

### Three Roles

1. **Host-Level Context (the glue)**
   External engines don't know what a host IS -- they just see an IP. ScottyScan's discovery and inventory phases produce:
   - OS identification (Windows build, Linux distro, network device type)
   - DNS/hostname resolution
   - Domain membership and role (DC, member server, workstation)
   - Installed software with versions

   This context attaches to every finding from every engine. "CVE-2025-15556 on 192.168.101.50" becomes "CVE-2025-15556 on ILAS3DB140 (SQL Server, Windows Server 2019, 7-Zip 23.01)."

2. **Active Validation (ground truth)**
   External engines report findings based on signatures and banners. ScottyScan plugins **actively test** the vulnerability (e.g., sending a real TLS ClientHello to confirm DHE cipher acceptance). A finding flagged by both OpenVAS (signature) and ScottyScan (active test) is corroborated with high confidence.

3. **Gap Coverage (authenticated checks)**
   Software-class plugins (7Zip-Version, flag rules engine) check things no network scanner can see -- installed software versions via remote registry/WMI. This is the same space as Vuls but for Windows, without needing an agent.

### Bridge to ScottyScan

ScottyScan needs the following to serve as a proper ScottyScan adapter:
- **Normalized JSONL emitter** -- parallel output matching the ScottyScan finding schema
- **Host context block** -- OS, software inventory, domain info as enrichment data that ScottyScan can attach to findings from ANY engine
- **Discovery export** -- ScottyScan's discovered host list as input to ScottyScan's target definitions, so all engines scan the same environment ScottyScan mapped

---

## Correlation Database & Workbench UI

### The Problem

Scan results from multiple engines produce thousands of findings across hundreds of hosts. Currently these live in flat CSVs and text reports -- workable for small scans, but unusable for:
- Correlating the same CVE across multiple engines
- Tracking remediation status over time
- Comparing scan-to-scan deltas ("what changed since last week?")
- Working directly from the data (assigning findings, marking false positives, exporting filtered sets)

### Scan Packages

A **scan package** is a single point-in-time snapshot containing:
- All findings from all enabled engines (normalized)
- Host context data (OS, software inventory, open ports)
- Engine metadata (versions, feed dates, scan profiles used)
- Timestamp and scan configuration

Scan packages are the atomic unit of comparison. Each full scan run produces one package. Packages are immutable once created -- remediation status and annotations are tracked as overlays, not mutations.

### Local Database

All scan packages and their metadata are stored in a **local SQLite database** (single file, zero infrastructure, portable across systems).

Core tables:

```
scan_packages
  id, timestamp, name, description, config_hash, engine_versions_json

hosts
  id, ip, hostname, os, os_version, domain, role, first_seen_package_id, last_seen_package_id

findings
  id, package_id, host_id, source_engine, cve_id, port, protocol, service,
  severity, cvss_score, title, detail, evidence, confidence,
  corroborated_by (comma-separated engine list)

software_inventory
  id, package_id, host_id, display_name, version, architecture, install_path

annotations
  id, finding_id, status (open, false_positive, accepted_risk, remediated, in_progress),
  assignee, note, timestamp, author

comparisons
  id, baseline_package_id, current_package_id, timestamp,
  new_findings_count, resolved_findings_count, changed_findings_count
```

Key design decisions:
- **SQLite, not a server database.** Must launch on any system without installing PostgreSQL/MySQL. The DB file can be copied, emailed, archived.
- **Findings are per-package.** The same CVE on the same host in two different scans is two separate finding rows. Comparison queries join across packages by (host_ip, cve_id, port).
- **Annotations are external to findings.** Marking something as a false positive doesn't modify the scan data. Annotations carry forward automatically -- if a finding recurs in a new package, its annotation from the previous package is inherited unless explicitly changed.

### Workbench UI

A **self-contained local web interface** that launches from the CLI and serves from localhost. No internet required. No cloud dependencies. Runs on any system with a browser.

```
scottyscan workbench                  # launch on default port 8484
scottyscan workbench --port 9090      # custom port
scottyscan workbench --package latest # open directly to most recent scan
```

Technology: embedded HTTP server (Python `http.server` / Go `net/http`) serving a single-page app. All data comes from the local SQLite DB. The UI is static HTML/CSS/JS bundled into the distribution -- no npm, no build step, no framework runtime.

#### Tab Structure

| Tab | Purpose |
|-----|---------|
| **Dashboard** | Executive view: severity breakdown pie/bar charts, top 10 hosts by finding count, engine coverage matrix, scan package metadata |
| **Hosts** | Searchable/sortable host table. Click a host to see all its findings, open ports, installed software, OS detail. Filter by OS, subnet, domain. |
| **Findings** | Master finding table across all engines. Filter by severity, CVE, engine, status (open/FP/remediated). Bulk status assignment. Click a finding for full detail + evidence. |
| **Software** | Software inventory view. Search/filter by app name, version, host. Highlight flagged versions. Export filtered lists for deployment scripts. |
| **Compare** | Select two scan packages. Side-by-side diff: new findings (red), resolved findings (green), unchanged (gray). Drill into any delta. |
| **Exports** | Generate filtered exports: CSV for Excel, JSONL for tooling, Markdown for reports, PDF for customer/CAB handoff. Pre-built export templates (e.g., "all critical+high open findings" or "remediation delta since last scan"). |

#### Working FROM the Workbench

The workbench is not just a viewer -- it's the daily operational interface:

- **Assign findings** to team members or groups
- **Mark false positives** with a note (persists across future scans)
- **Set accepted risk** with expiry dates and justification
- **Track remediation** status per finding per host
- **Create remediation tickets** -- export filtered finding sets in formats compatible with ticketing systems (Jira CSV, ServiceNow import)
- **Generate CAB documents** -- before/after comparison reports for change advisory boards
- **Push to deployment** -- export IP lists for specific software findings (e.g., "all hosts with 7-Zip < 24.9") for feeding into deployment tools

#### Scan Package Comparison

The comparison engine is central to the workflow. After each scan cycle:

1. New package is imported
2. Auto-comparison runs against the previous package (or a user-selected baseline)
3. Delta summary is generated:
   - **New findings**: present in current but not baseline (new vulnerabilities or newly discovered hosts)
   - **Resolved findings**: present in baseline but not current (remediation confirmed)
   - **Persistent findings**: present in both (unchanged, still needs attention)
   - **Changed findings**: same CVE+host but severity/detail changed (engine updated its assessment)
   - **New hosts**: hosts discovered in current that weren't in baseline
   - **Lost hosts**: hosts in baseline that didn't respond in current
4. Annotations from the baseline package carry forward to matching findings in the current package

The comparison view is designed for the weekly/monthly remediation review:
- "Show me everything that was fixed since last scan" -> green list for CAB
- "Show me everything new since last scan" -> red list for triage
- "Show me everything that's been open for 3+ scans" -> amber list for escalation

---

## Implementation Priority

### Phase 1: ScottyScan Core (IN PROGRESS)
- [x] Plugin architecture with Register-Validator pattern
- [x] Interactive TUI menu system with keyboard navigation
- [x] Host discovery with batched async port scanning
- [x] Scan execution engine with scoped test matrix
- [x] Real-time console output during scanning
- [x] CSV and text report output
- [x] Verbose per-run logging
- [ ] Scan mode end-to-end testing
- [ ] Validate mode end-to-end testing
- [ ] OS fingerprinting (merge from legacy: WMI, SSH banner, SMB)
- [ ] Software inventory engine (merge from legacy: registry, PSRemoting, WMI)
- [ ] Flag rules engine (merge from legacy: version comparison rules)
- [ ] Normalized JSONL output (ScottyScan finding schema)

### Phase 2: ScottyScan Foundation
- [ ] Plugin base class and interface definition
- [ ] Config system with YAML loading and validation
- [ ] CLI skeleton (`plugin list`, `plugin enable/disable`, `plugin status`)
- [ ] Normalized finding schema (Pydantic models matching the JSON spec above)
- [ ] Basic orchestrator (sequential scan execution)
- [ ] ScottyScan adapter (bridge PowerShell scanner into ScottyScan plugin interface)

### Phase 3: First External Engines
- [ ] Nuclei adapter (simplest -- single binary, JSONL output)
- [ ] Nmap adapter (well-known XML output)
- [ ] Result normalization for both engines
- [ ] Finding deduplication logic (CVE + host + port matching)
- [ ] Corroboration flagging (detected by 2+ engines)

### Phase 4: Correlation Database
- [ ] SQLite schema: scan_packages, hosts, findings, software_inventory, annotations, comparisons
- [ ] Package import pipeline (ingest normalized JSONL from any engine into DB)
- [ ] Host context enrichment (attach ScottyScan discovery data to all findings)
- [ ] Annotation persistence and carry-forward across packages
- [ ] Scan package comparison engine (new/resolved/persistent/changed delta)
- [ ] CLI queries (`scottyscan query --cve CVE-2024-1234 --status open`)

### Phase 5: Workbench UI
- [ ] Embedded HTTP server with static SPA
- [ ] Dashboard tab (severity charts, host rankings, engine matrix)
- [ ] Hosts tab (searchable/sortable with drill-down)
- [ ] Findings tab (master table with filters, bulk actions, status assignment)
- [ ] Software tab (inventory view with flag highlighting)
- [ ] Compare tab (package diff with new/resolved/persistent coloring)
- [ ] Exports tab (filtered CSV, JSONL, Markdown, PDF generation)

### Phase 6: Heavy Engines & Polish
- [ ] OpenVAS/GVM adapter (service management, GMP protocol)
- [ ] Vuls adapter (multi-database update orchestration)
- [ ] Update management system with scheduling
- [ ] CVE enrichment (CISA KEV, EPSS scores, exploit-db cross-reference)
- [ ] Async/parallel scan execution across engines
- [ ] Custom plugin loader and manifest validation

---

## Notes for Claude Code

- Steven works in mixed Windows/Linux environments. The orchestrator should be cross-platform where possible, but engine backends (especially OpenVAS) are Linux-only. Flag platform requirements clearly.
- Steven's existing PowerShell toolkit (`Discover-And-Inventory.ps1`, `Deploy-SoftwareUpdate.ps1`) should be interoperable -- consider a bridge plugin or import mechanism for his existing network discovery data.
- CSV output is critical for Steven's workflow -- he uses Excel for executive reporting and master tracking. The workbench must always support CSV export as a first-class citizen.
- All scan operations should be non-destructive by default. Include dry-run and scan-only modes.
- Logging should be comprehensive -- Steven operates in SOC2 environments where audit trails matter.
- Consider Docker Compose for OpenVAS/GVM stack to simplify dependency hell.
- The correlation database and workbench UI must be zero-infrastructure: SQLite file + embedded HTTP server + static HTML/JS. No external database servers, no npm, no cloud services. Must work air-gapped.
- The workbench is the PRIMARY operational interface, not an afterthought. Design the database schema and comparison engine first, then build the UI on top. The CLI and CSV exports are fallbacks, not the main workflow.
- Scan package comparison is the killer feature for Steven's remediation tracking workflow. The "what changed since last scan" question drives weekly CAB meetings and monthly compliance reviews. Get this right early.
