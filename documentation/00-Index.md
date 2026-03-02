# ScottyScan Documentation

## What is ScottyScan?

ScottyScan is a PowerShell-based tool for network discovery, vulnerability scanning, software inventory, and OpenVAS finding validation. It consolidates multiple standalone scanning scripts into a single menu-driven, plugin-based scanner that runs from an administrative PowerShell console on a Windows workstation.

ScottyScan is built for IT infrastructure and security teams who need to:

- Discover hosts across CIDR ranges and fingerprint their operating systems
- Check for known vulnerabilities using pluggable test modules
- Inventory installed software on Windows hosts and flag outdated or vulnerable versions
- Validate whether findings reported by OpenVAS (Greenbone Community Edition) have been remediated

All of this runs through an interactive terminal UI (TUI) with keyboard navigation, or through CLI parameters for scripted/scheduled execution.

---

## Table of Contents

| Chapter | File | Description |
|---------|------|-------------|
| 00 | [00-Index.md](00-Index.md) | This file -- documentation home and table of contents |
| 01 | [01-Getting-Started.md](01-Getting-Started.md) | Prerequisites, project structure, first run, CLI examples |
| 02 | [02-Modes-of-Operation.md](02-Modes-of-Operation.md) | Scan, List, and Validate modes in detail |
| 03 | [03-Interactive-TUI.md](03-Interactive-TUI.md) | Menu system, keyboard controls, state machine flow |
| 04 | [04-Plugin-System.md](04-Plugin-System.md) | Plugin API, writing new plugins, existing plugin reference |
| 05 | [05-Host-Discovery.md](05-Host-Discovery.md) | Port scanning, OS fingerprinting, batched async probes |
| 06 | [06-Software-Version-Check.md](06-Software-Version-Check.md) | Software inventory, flag rules, version comparison engine |
| 07 | [07-Output-and-Reporting.md](07-Output-and-Reporting.md) | CSV outputs, summary reports, logs, discovery CSVs |
| 08 | [08-Configuration.md](08-Configuration.md) | scottyscan.json, CLI parameters, persistent state |
| 09 | [09-OpenVAS-Integration.md](09-OpenVAS-Integration.md) | Validate mode, OpenVAS CSV format, Greenbone CE setup |
| 10 | [10-Platform-Architecture.md](10-Platform-Architecture.md) | Platform architecture spec (multi-engine module vision) |
| 11 | [11-Development-Guide.md](11-Development-Guide.md) | PowerShell gotchas, testing, parser checks, contributing |
| 12 | [12-Function-Reference.md](12-Function-Reference.md) | All functions with line numbers, parameters, purpose |
| 13 | [13-Environment-Research.md](13-Environment-Research.md) | Legacy scanner analysis, target environment notes |

---

## Where to Start

### New Users

If you want to run ScottyScan against your environment:

1. Start with **[01-Getting-Started.md](01-Getting-Started.md)** for prerequisites and your first run.
2. Read **[02-Modes-of-Operation.md](02-Modes-of-Operation.md)** to understand which mode fits your use case.
3. Read **[03-Interactive-TUI.md](03-Interactive-TUI.md)** if you are using the interactive menu (the default when you launch without CLI flags).
4. Review **[07-Output-and-Reporting.md](07-Output-and-Reporting.md)** to understand what files ScottyScan produces and where to find them.

### Security Teams Validating OpenVAS Findings

1. Start with **[01-Getting-Started.md](01-Getting-Started.md)** for setup.
2. Go directly to **[09-OpenVAS-Integration.md](09-OpenVAS-Integration.md)** for Validate mode specifics and the expected CSV format.
3. Review **[04-Plugin-System.md](04-Plugin-System.md)** to understand how findings are matched to plugins via NVT patterns.

### Plugin Developers

1. Read **[04-Plugin-System.md](04-Plugin-System.md)** for the plugin API, available helpers, and the `Register-Validator` contract.
2. Read **[11-Development-Guide.md](11-Development-Guide.md)** for PowerShell gotchas that will save you hours of debugging.
3. Use **[12-Function-Reference.md](12-Function-Reference.md)** to understand the internal helper functions available in `TestBlock` scriptblocks.

### Contributors and Maintainers

1. Read **[10-Platform-Architecture.md](10-Platform-Architecture.md)** for the longer-term platform vision.
2. Read **[11-Development-Guide.md](11-Development-Guide.md)** for the development workflow, parser validation, and known issues.
3. Use **[12-Function-Reference.md](12-Function-Reference.md)** as a map of the codebase.
4. Review **[13-Environment-Research.md](13-Environment-Research.md)** for context on the target environment and legacy tools this project replaces.

---

## AI Context Companion

The file `CLAUDE.md` in the project root serves as a machine-readable companion to this documentation. It contains the same architectural information in a format optimized for AI coding assistants (Claude Code, Copilot, etc.) and is kept in sync with the project's actual state. If you are working with an AI assistant on this codebase, `CLAUDE.md` provides the context it needs to understand the project structure, plugin API, and known issues.

---

## Project Status

ScottyScan v1.0.0 has been tested in List mode against 14 hosts with all 4 plugins. The core pipeline -- host loading, discovery, plugin scanning, real-time output, CSV/report generation -- works end-to-end. The interactive TUI menu system has been fully rewritten and tested.

See [01-Getting-Started.md](01-Getting-Started.md) for current capabilities and [11-Development-Guide.md](11-Development-Guide.md) for what still needs testing.
