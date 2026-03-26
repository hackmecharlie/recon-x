# RECON-X

Production-ready CLI tool for automated security reconnaissance.

RECON-X scans targets (IP, CIDR, hostnames, URLs), identifies exposed services and common security issues (SMB, TLS, web headers, RDP/VNC/Telnet), enriches findings with CVE context, and generates professional HTML/PDF reports.

## Why RECON-X

- Fast and practical for real assessments
- Modular checks across network, SMB, TLS, and web surfaces
- Resume support for interrupted scans
- Interactive HTML report + printable PDF output
- Clean CLI workflow with scan profiles and selective module modes

## Features

- Target parsing: single IP, CIDR, ranges, hostnames, URLs
- Port and service discovery (profile-based depth)
- SMB checks and enumeration outputs
- TLS certificate and cipher/protocol analysis
- Web security checks (headers, clickjacking, banners)
- Screenshot capture for web targets
- CVE lookup correlation (optional)
- Risk scoring and severity grouping
- HTML + PDF reporting

## Requirements

- Python 3.10+
- Linux/macOS/Windows
- `nmap` installed and available in PATH
- Chromium for screenshots (Playwright)
- System libs for PDF generation (WeasyPrint)

## Install and Permissions

From project root:

```bash
chmod +x setup.sh run.sh
./setup.sh
```

What `setup.sh` does:

- checks Python 3.10+
- attempts Linux system dependency install (`nmap`, `libpango-1.0-0`, `libpangoft2-1.0-0`)
- creates and activates `.venv`
- installs Python dependencies
- installs RECON-X in editable mode
- installs Playwright Chromium
- runs post-setup verification checks

If system packages cannot be installed automatically (no `sudo`/root), install manually:

```bash
sudo apt-get update
sudo apt-get install -y nmap libpango-1.0-0 libpangoft2-1.0-0
```

## Quick Start

### One-time setup

```bash
chmod +x setup.sh run.sh
./setup.sh
```

### Run scans

```bash
./run.sh --targets 192.168.1.100 --title "Quick Check"
./run.sh --targets 10.0.0.0/24 --profile full --title "Internal Audit"
./run.sh --input target.txt --profile normal --concurrency 10 --yes
```

### Alternative: direct command (inside venv)

```bash
source .venv/bin/activate
recon-x scan --targets 192.168.1.100 --profile quick
```

## Main Commands

### Start scan

```bash
recon-x scan --targets 192.168.1.0/24 --profile quick
```

### Resume interrupted scan

```bash
recon-x resume --output-dir ./output
```

### Regenerate report from existing scan folder

```bash
recon-x report ./output/scan_YYYYMMDD_HHMMSS_xxxxxxxx --format both
```

### Show CLI help

```bash
recon-x --help
recon-x scan --help
```

## Important Scan Options

- `--targets` / `-t`: inline targets (comma-separated)
- `--input` / `-i`: targets file
- `--profile` / `-p`: `quick`, `normal`, `full`
- `--concurrency` / `-c`: parallel target workers
- `--timeout`: per-target timeout in seconds
- `--no-screenshots`: disable screenshot capture
- `--no-cve`: skip CVE correlation
- `--yes` / `-y`: non-interactive confirmation

Selective mode flags:

- `--ports-only`
- `--smb-only`
- `--web-only`
- `--tls-only`
- `--screenshots-only`

## Scan Profiles

- `quick`: top 100 ports, faster pass
- `normal`: top 1000 ports + standard checks
- `full`: deeper coverage + extended checks

## Supported Target Formats

- `192.168.1.100`
- `10.0.0.0/24`
- `10.0.0.10-10.0.0.50`
- `internal.example.com`
- `https://app.example.com`

## Output Structure

```text
output/
└── scan_YYYYMMDD_HHMMSS_<title>_<id>/
    ├── report.html
    ├── report.pdf
    ├── checkpoint.json
    ├── cve_cache.json
    └── screenshots/
```

## Reporting

The HTML report includes:

- Executive summary and severity stats
- Security dashboard charts
- Findings table and detailed findings
- Ports / headers / certificates / screenshots
- Appendix with target-level status data

## SMB Coverage (high level)

SMB module includes practical security checks and enumeration-focused outputs such as:

- SMBv1, signing policy, null session, guest access
- Default/admin share exposure
- Share read/write access checks
- Domain and user enumeration outputs (when available)
- Password policy indicators
- Printer and sensitive-file discovery signals

## Configuration

Default settings are in:

- `config/settings.yaml`

Tune concurrency, timeouts, logging, screenshot behavior, and CVE settings there.

## Troubleshooting

### `recon-x: command not found`

Use the venv and editable install:

```bash
source venv/bin/activate
pip install -e .
```

### Reports generated but empty sections

- Ensure scan profile and module flags collected the required data
- Re-run using `--profile normal` or `--profile full`
- Verify you are opening the newly generated file in latest output directory

### SMB import/check failures

- Confirm dependencies installed from `requirements.txt`
- Run from activated venv

## Legal

Use only on systems you own or have explicit written authorization to test.

Unauthorized scanning can violate laws and policy.
