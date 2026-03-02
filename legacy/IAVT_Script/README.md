# Infra Asset + OpenVAS Toolkit

## Overview

The Infra Asset + OpenVAS Toolkit is designed to streamline infrastructure asset management and vulnerability scanning workflows. It consists of two main components:

- **Asset Tracker Workflow:** Discovers and tracks infrastructure assets, maintaining an up-to-date inventory.
- **OpenVAS Builder Workflow:** Builds and updates OpenVAS scan configurations based on asset data, facilitating targeted vulnerability assessments.

This toolkit aims to provide a comprehensive, automated approach to asset discovery and vulnerability management, integrating asset tracking with OpenVAS scanning capabilities.

---

## Folder Structure

```
IW_IAVT/
├── infra_asset_vuln_tool.py      # Main asset discovery and vulnerability scanning script
├── openvas_25_builder.py         # OpenVAS 2.5 scan configuration builder and updater
├── requirements.txt              # Python dependencies
├── README.md                     # This documentation file
├── LICENSE                      # License information
└── configs/                      # Directory for configuration files and templates
    ├── openvas_config_template.xml
    └── other_config_files.xml
```

---

## Setup Instructions

### 1. Create a Virtual Environment

It is highly recommended to use a Python virtual environment to isolate dependencies.

#### macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

#### Windows (PowerShell)

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 2. Install Dependencies

Once the virtual environment is activated, install required packages:

```bash
pip install -r requirements.txt
```

---

## Scripts Documentation

### 1. `infra_asset_vuln_tool.py`

#### Purpose

Discovers infrastructure assets on specified network ranges or hosts, tracks asset status, and performs vulnerability scanning using integrated tools or APIs.

#### Key Features

- Supports scanning by IP range, CIDR, or individual hosts.
- Tracks asset status over time (e.g., new, active, removed).
- Outputs JSON or CSV reports for asset inventory and vulnerabilities.
- Can be integrated with external vulnerability scanners.

#### Usage

```bash
python infra_asset_vuln_tool.py --help
```

##### Example Command

```bash
python infra_asset_vuln_tool.py --target 192.168.1.0/24 --output results.json --scan-vulns
```

##### Arguments

- `--target`: IP address, range, or CIDR block to scan.
- `--output`: Path to output file (JSON or CSV).
- `--scan-vulns`: Enable vulnerability scanning on discovered assets.
- `--config`: Optional path to a configuration file for custom settings.

---

### 2. `openvas_25_builder.py`

#### Purpose

Builds and updates OpenVAS 2.5 scan configuration XML files based on asset data and user-defined parameters.

#### Key Features

- Supports build mode (create new scan configs) and update mode (modify existing configs).
- Allows filtering assets by status, tags, or other metadata.
- Generates OpenVAS-compatible XML scan configuration files.
- Supports integration with asset tracking data from `infra_asset_vuln_tool.py`.

#### Usage

```bash
python openvas_25_builder.py --help
```

##### Example Commands

- **Build mode:**

```bash
python openvas_25_builder.py --mode build --assets assets.json --output scan_config.xml
```

- **Update mode:**

```bash
python openvas_25_builder.py --mode update --existing-config scan_config.xml --assets updated_assets.json --output updated_scan_config.xml
```

##### Arguments

- `--mode`: Operation mode (`build` or `update`).
- `--assets`: JSON file containing asset data.
- `--existing-config`: Existing OpenVAS config XML file (required for update mode).
- `--output`: Output path for the generated scan config XML.
- `--filter-status`: Filter assets by status (e.g., active, new).
- `--tags`: Filter assets by tags or labels.

---

## Configuration and Usage Details

### Build Mode

- Starts with a base XML template.
- Adds targets based on asset IPs and filters.
- Generates a new OpenVAS scan configuration file.

### Update Mode

- Loads an existing OpenVAS scan configuration.
- Updates or removes targets based on latest asset data.
- Preserves user-defined scan settings where possible.

---

## Status Values and Column Logic

The asset tracking workflow uses the following status values to indicate asset lifecycle:

- **New:** Asset discovered for the first time.
- **Active:** Asset seen in current and previous scans.
- **Removed:** Asset not seen in the current scan but present previously.
- **Ignored:** Asset excluded based on filters or user settings.

Columns in output reports include:

- **IP Address:** Asset IP.
- **Hostname:** Resolved hostname, if available.
- **Status:** Current status (New, Active, Removed, Ignored).
- **Last Seen:** Timestamp of last detection.
- **Tags:** User-defined labels or categories.

---

## Interoperation of Tools

- `infra_asset_vuln_tool.py` produces asset inventories with status and metadata.
- `openvas_25_builder.py` consumes these inventories to generate targeted OpenVAS scan configurations.
- This separation allows flexible workflows: asset discovery and vulnerability scanning can be decoupled or integrated.
- Users can manually review or modify asset inventories before building scan configs.

---

## Troubleshooting

- **Virtual environment activation fails:** Ensure Python 3 is installed and environment paths are correct.
- **Dependencies fail to install:** Upgrade `pip` and verify network connectivity.
- **OpenVAS config XML invalid:** Validate XML syntax and ensure asset IPs are correctly formatted.
- **Assets missing from scans:** Check IP ranges and filters; verify network accessibility.
- **Scan configurations not applied:** Confirm OpenVAS version compatibility and configuration file paths.

---

## Requirements

- Python 3.6 or higher
- `lxml` for XML processing
- `requests` for API interactions (if applicable)
- Network access to target assets
- OpenVAS 2.5 or compatible installation for scan execution

---

## Example Commands Summary

### Infra Asset Vulnerability Tool

```bash
python infra_asset_vuln_tool.py --target 10.0.0.0/16 --output assets.json --scan-vulns
```

### OpenVAS 2.5 Builder

```bash
python openvas_25_builder.py --mode build --assets assets.json --output openvas_scan_config.xml
```

```bash
python openvas_25_builder.py --mode update --existing-config openvas_scan_config.xml --assets updated_assets.json --output updated_scan_config.xml
```

---

## Conventions and Notes

- Asset inventory files are stored in JSON format to preserve metadata.
- Scan configuration XML files follow OpenVAS 2.5 schema.
- Naming conventions for scan configs include timestamps and environment tags for clarity (e.g., `scan_config_20240427_prod.xml`).
- Scan tracking is maintained by correlating asset statuses with scan results to prioritize remediation efforts.
- Users should regularly update asset inventories and scan configs to maintain accuracy.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

# Infra Asset + OpenVAS Toolkit

A small toolkit for building a clean **Asset Tracker** workbook and a companion **OpenVAS** workbook so you can trend vulnerabilities over time.

- `infra_asset_vuln_tool.py` → builds/updates `Asset_Tracker.xlsx`
- `openvas_25_builder.py` → builds/extends `OpenVAS_25.xlsx`

No scanners, configs, or XML here. These scripts just **ingest CSV/Excel you already have** and write new Excel files.

---

## Folder layout (example)

```
IW_IAVT/
├─ files/
│  ├─ physical_inventory_2024.csv
│  ├─ virtual_inventory_2024.csv
│  ├─ vsphere_vmlist_20251015-111715.csv
│  └─ 10-13-2025_evidence_vonahi/
│     └─ vulnerability_scan/
│        └─ detailedresults.csv
├─ outputs/
│  ├─ Asset_Tracker.xlsx          # built by infra_asset_vuln_tool.py
│  └─ OpenVAS_25.xlsx             # built by openvas_25_builder.py
├─ infra_asset_vuln_tool.py
├─ openvas_25_builder.py
├─ requirements.txt
└─ README.md
```

> For OpenVAS, point `--openvas-root` at the **folder** that contains (somewhere under it) a `detailedresults.csv`. The builder finds the newest one recursively.

---

## First‑time setup

### 1) Create & activate a virtualenv

**macOS/Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell)**
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2) Install deps
```bash
pip install -r requirements.txt
```

---

## Script 1 — Asset Tracker Builder / Updater

**File:** `infra_asset_vuln_tool.py`  
**Output:** `outputs/Asset_Tracker.xlsx`

### Build from scratch (config-first; CLI can override)
```bash
python infra_asset_vuln_tool.py build-asset-tracker --config config.yaml
```

**Example `config.yaml`:**
```yaml
physical_csv: files/physical_inventory_2024.csv
virtual_csv: files/virtual_inventory_2024.csv
vcenter_csv: files/vsphere_vmlist_20251015-111715.csv
openvas_root: files/10-13-2025_evidence_vonahi
output: outputs/Asset_Tracker.xlsx
```

**Override at runtime:**
```bash
python infra_asset_vuln_tool.py build-asset-tracker \
  --config config.yaml \
  --vcenter-csv files/vsphere_vmlist_20251020-093201.csv \
  --openvas-root files/10-27-2025_evidence_vonahi
```

### Update an existing tracker (no YAML required)
```bash
# Refresh with a new vCenter CSV
python infra_asset_vuln_tool.py update-asset-tracker \
  --tracker outputs/Asset_Tracker.xlsx \
  --vcenter-csv files/vsphere_vmlist_20251020-093201.csv

# Refresh with a new OpenVAS root
python infra_asset_vuln_tool.py update-asset-tracker \
  --tracker outputs/Asset_Tracker.xlsx \
  --openvas-root files/10-27-2025_evidence_vonahi
```

### Asset Tracker rules (high‑level)
- **Field mapping** (your spec): unifies physical + virtual into `asset_tracker` with columns: `name, ip_address, data_classification, type, purpose, dns_name, location, status, svc_tag, notes`.
- **vCenter wins on status**: `PoweredOn/PoweredOff` from vCenter; missing in vCenter → `not in vcenter`.
- **OpenVAS signals**:
  - If not in vCenter but present in OpenVAS → `Online`.
  - Add net‑new IPs seen in OpenVAS as `found in scan` (rare).
- **Filters/UI**: auto-fit columns; auto-filter applied (we exclude `PoweredOff` by default).

**Status values** you’ll see:
- `PoweredOn`, `PoweredOff`, `not in vcenter`, `Online`, `not in scan` (baseline host with no current findings and no prior status)

---

## Script 2 — OpenVAS Workbook Builder

**File:** `openvas_25_builder.py`  
**Reads:** `outputs/Asset_Tracker.xlsx`  
**Output:** `outputs/OpenVAS_25.xlsx`

### Run
```bash
python openvas_25_builder.py \
  --asset-tracker ./outputs/Asset_Tracker.xlsx \
  --openvas-root ./files/10-13-2025_evidence_vonahi \
  --output ./outputs/OpenVAS_25.xlsx
```

### What it writes
- **OpenVAS_Summary** (always first):
  - `high_count_now`, `medium_count_now`, `totals_now` (current scan; H+M only)
  - `baseline-YYMMDD-totals` on the first run
  - `scan-YYMMDD-totals` for each subsequent scan date
  - `asset_status`, `asset_location`, `asset_source` (refreshed from tracker)
  - Sorted by `totals_now`, then `high_count_now`, then `medium_count_now` (desc)
- **OpenVAS_YYMMDD**: HM‑only details for that scan (CVSS/QoD numeric)
- **_meta**: appended each run (CSV path, scan_date, details sheet name, timestamp)

### Important behaviors
- **No duplicate scan columns**: If the same scan date already exists (as baseline or a prior `scan-…-totals`), the script **updates NOW + asset fields** only and prints a note.
- **Strict intake**: parsing uses the OpenVAS **IP** and **Hostname** columns (normalized lower-case) and filters out bogus IP strings.
- **Better software parsing** (under the hood): we prioritize `Affected Software/OS` when product detection is missing. (Software tabs are currently disabled per your request.)

---

## Troubleshooting

- **“No detailedresults.csv found under …”**  
  The builder now prints hints (similar CSVs, found ZIPs, and tips). If your scan is zipped, unzip it so `detailedresults.csv` exists beneath `--openvas-root`.

- **Excel filter looks stale on first open (Mac)**  
  Close/reopen if Excel cached the view. We apply auto-fit and filters programmatically.

- **Version mismatch (`|` type in annotations)**  
  Use Python 3.10+, or we’ve already made the script 3.9‑compatible using `typing.Optional`.

---

## Requirements

```
pandas>=2.2,<2.3
openpyxl>=3.1.2,<3.2
PyYAML>=6.0.1,<7
```

Install with:
```bash
pip install -r requirements.txt
```

---

## Examples

**Build Asset Tracker with config + overrides**
```bash
python infra_asset_vuln_tool.py build-asset-tracker \
  --config config.yaml \
  --openvas-root files/10-27-2025_evidence_vonahi \
  --vcenter-csv files/vsphere_vmlist_20251027-081500.csv
```

**Update Asset Tracker with new OpenVAS only**
```bash
python infra_asset_vuln_tool.py update-asset-tracker \
  --tracker outputs/Asset_Tracker.xlsx \
  --openvas-root files/11-02-2025_evidence_vonahi
```

**Build/extend OpenVAS workbook**
```bash
python openvas_25_builder.py \
  --asset-tracker outputs/Asset_Tracker.xlsx \
  --openvas-root files/11-02-2025_evidence_vonahi \
  --output outputs/OpenVAS_25.xlsx
```

---

### Conventions & Notes
- vCenter CSV names like `vsphere_vmlist_YYYYMMDD-HHMMSS.csv` carry useful timestamps.
- Summary per‑scan columns are **H+M totals only**: first is `baseline-YYMMDD-totals`, then `scan-YYMMDD-totals` on each new date.
- Asset fields are refreshed from the tracker every run so status stays in sync with vCenter and OpenVAS signals.
