# ScottyScan

An open-source, PowerShell-based vulnerability scanner for IT environments. ScottyScan discovers networked hosts, checks for known vulnerabilities, inventories installed software, and validates whether OpenVAS findings have been remediated -- all through an interactive menu-driven interface with a plugin architecture.

## Features

- **Network Discovery** -- CIDR sweep with ping + TCP probes and OS fingerprinting
- **Vulnerability Scanning** -- Plugin-based checks for specific CVEs and misconfigurations
- **Software Inventory** -- Remote enumeration of installed software on Windows hosts
- **Compliance Checking** -- Flag outdated or vulnerable software versions against configurable rules
- **OpenVAS Validation** -- Import OpenVAS CSV findings and re-test to confirm remediation
- **Persistent Config** -- Remembers your selections between runs

## Modes

| Mode | Description |
|------|-------------|
| **Scan** | Discover hosts on a CIDR, fingerprint OS, run selected plugins |
| **List** | Skip discovery, read IPs from a file, run selected plugins |
| **Validate** | Import OpenVAS CSV, match findings to plugins, test and produce a validated report |

## Plugins

| Plugin | Description |
|--------|-------------|
| DHEater-TLS | D(HE)ater on SSL/TLS (CVE-2002-20001) |
| DHEater-SSH | D(HE)ater on SSH |
| SSH1-Deprecated | Deprecated SSH-1 protocol detection |
| 7Zip-Version | Outdated 7-Zip via remote registry/WMI |

New plugins can be created from `plugins/_PluginTemplate.ps1`.

## Status

Early development -- see the [issue tracker](https://github.com/scrampker/ScottyScan/issues) for planned work and progress.

## License

TBD
