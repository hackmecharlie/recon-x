<div align="center">

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗      ██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║      ╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗ ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════╝ ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║      ██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝      ╚═╝  ╚═╝
```

**A polished command-line security reconnaissance framework**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)](.)
[![Requires nmap](https://img.shields.io/badge/Requires-nmap-orange?style=flat-square)](https://nmap.org)
[![License](https://img.shields.io/badge/Use-Authorized_Targets_Only-red?style=flat-square)](.)

*Scan → Discover → Report — all from one tool.*

</div>

---

## 🗺️ Table of Contents

- [What is RECON-X?](#-what-is-recon-x)
- [What it can do](#-what-it-can-do)
- [Before you begin — Requirements](#-before-you-begin--requirements)
- [Installation](#-installation)
  - [Linux / macOS](#linuxmacos)
  - [Windows](#windows)
- [Your first scan](#-your-first-scan)
- [All the ways to scan](#-all-the-ways-to-scan)
- [Scan profiles explained](#-scan-profiles-explained)
- [Supported target formats](#-supported-target-formats)
- [Understanding your output](#-understanding-your-output)
- [Configuration](#️-configuration)
- [Troubleshooting](#-troubleshooting)
- [Keeping RECON-X updated](#-keeping-recon-x-updated)
- [Legal notice](#️-legal-notice)

---

## 🔍 What is RECON-X?

RECON-X is a **security reconnaissance tool** — meaning it scans computers, servers, and networks to discover what's running, what's exposed, and what might be vulnerable. It's built for security professionals and IT admins who need a fast, reliable way to audit their own infrastructure.

You give it a target (an IP address, a range of IPs, or a website URL), pick a scan depth, and it does the rest — then hands you a clean, professional HTML or PDF report you can share with your team or clients.

> **Not a hacker tool.** RECON-X is for scanning systems *you own* or have *written permission* to test. Unauthorized scanning is illegal.

---

## ✅ What it can do

| Category | What gets checked |
|---|---|
| 🌐 **Network** | Open ports, running services, host discovery |
| 🗂️ **SMB / File Shares** | Windows share exposure, SMB security posture |
| 🔒 **TLS / SSL** | Certificate validity, weak ciphers, expiry dates |
| 🕸️ **Web** | Security headers, clickjacking risks, banner exposure |
| 📸 **Screenshots** | Automatic browser screenshots of web targets |
| 🐛 **CVE Lookup** | Correlates findings with known vulnerability data |
| 📄 **Reports** | Interactive HTML report + printable PDF |

---

## 📋 Before you begin — Requirements

Before installing RECON-X, make sure you have the following on your machine.

> **Not sure if you have these?** Open a terminal (or PowerShell on Windows) and run the "Check" commands below.

### Required software

| Software | Why it's needed | Minimum version | How to check |
|---|---|---|---|
| **Python** | Runs RECON-X | 3.10 or newer | `python --version` |
| **nmap** | Does the actual port scanning | Any recent version | `nmap --version` |
| **Chromium** | Takes screenshots of web pages | Auto-installed by setup | — |

### Installing missing requirements

**Python** → Download from [python.org/downloads](https://python.org/downloads). On Windows, tick **"Add Python to PATH"** during install.

**nmap** →
- Linux (Ubuntu/Debian): `sudo apt-get install nmap`
- macOS: `brew install nmap`  
- Windows: Download from [nmap.org](https://nmap.org), install, then restart PowerShell

Chromium is handled automatically during the RECON-X setup — you don't need to install it yourself.

---

## 💾 Installation

### Linux/macOS

Open a terminal and follow these steps one by one:

**Step 1 — Navigate to the RECON-X folder**
```bash
cd /path/to/recon-x/recon-x
```
*(Replace `/path/to/recon-x` with the actual location where you extracted or cloned RECON-X)*

**Step 2 — Make the setup script runnable**
```bash
chmod +x setup.sh run.sh
```

**Step 3 — Run the setup**
```bash
./setup.sh
```

That's it. The script will automatically:
- ✔ Check your Python version
- ✔ Install system packages (if possible)
- ✔ Create an isolated Python environment (`.venv`)
- ✔ Install all Python dependencies
- ✔ Install Chromium for screenshots
- ✔ Verify everything is working

<details>
<summary>⚠️ If setup fails with a permission error on system packages</summary>

Run these manually first, then try `./setup.sh` again:

```bash
sudo apt-get update
sudo apt-get install -y nmap libpango-1.0-0 libpangoft2-1.0-0
```

</details>

---

### Windows

Open **PowerShell** and follow these steps:

**Step 1 — Navigate to the RECON-X folder**
```powershell
cd C:\path\to\recon-x\recon-x
```

**Step 2 — Allow the setup script to run**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
*(This is temporary and only affects the current PowerShell window)*

**Step 3 — Run the setup**
```powershell
.\setup_windows.ps1
```

The script will handle everything automatically — same as on Linux/macOS.

> **nmap on Windows:** If nmap wasn't found, download and install it from [nmap.org](https://nmap.org), then restart PowerShell and run the setup again.

---

## 🚀 Your first scan

Once installed, try a quick test scan to make sure everything works:

**Linux / macOS:**
```bash
./run.sh --targets 192.168.1.100 --profile quick --title "My First Scan"
```

**Windows:**
```bat
.\run_windows.bat --targets 192.168.1.100 --profile quick --title "My First Scan"
```

Replace `192.168.1.100` with the IP address of a machine you own. RECON-X will scan it, then save a report in the `output/` folder. Open the `.html` file in any browser to see your results.

---

## 🛠️ All the ways to scan

### Scan a single target
```bash
./run.sh --targets 192.168.1.100 --profile normal
```

### Scan multiple targets at once
```bash
./run.sh --targets 192.168.1.100,10.0.0.5,internal.example.com --profile normal
```

### Scan from a file (one target per line)
```bash
./run.sh --input targets.txt --profile normal --concurrency 10 --yes
```

### Scan an entire network range
```bash
./run.sh --targets 192.168.1.0/24 --profile quick
```

### Resume a scan that was interrupted
```bash
recon-x resume --output-dir ./output
```

### Regenerate a report from existing scan data
```bash
recon-x report ./output/scan_YYYYMMDD_HHMMSS_xxxxxxxx --format both
```

You can also include empty or unreachable hosts in a regenerated report:
```bash
recon-x report ./output/scan_YYYYMMDD_HHMMSS_xxxxxxxx --format both --include-empty-targets --include-unreachable-targets
```

### Run specific checks only

| Flag | What it does |
|---|---|
| `--ports-only` | Only scan for open ports |
| `--smb-only` | Only check SMB / file shares |
| `--web-only` | Only check web targets |
| `--tls-only` | Only check TLS/SSL certificates |
| `--screenshots-only` | Only capture screenshots |

### SMB authentication examples

RECON-X can prompt for SMB credentials automatically when needed, or you can provide them directly:

```bash
recon-x scan -t 192.168.1.100 --smb-only --smb-username user --smb-password secret --smb-domain WORKGROUP
```

If you do not supply credentials on the command line, RECON-X will ask you securely during scan startup.

### All available options

| Option | Short | Description |
|---|---|---|
| `--targets` | `-t` | One or more targets, comma-separated |
| `--input` | `-i` | Path to a file with one target per line |
| `--profile` | `-p` | Scan depth: `quick`, `normal`, or `full` |
| `--concurrency` | `-c` | How many targets to scan in parallel |
| `--timeout` | | Max seconds to spend on each target |
| `--output-dir` | `-o` | Directory where scan output is saved |
| `--title` | | A label for this scan (used in output folder name) |
| `--no-screenshots` | | Disable screenshot capture to speed up scanning |
| `--no-cve` | | Skip CVE lookup and save API calls |
| `--auto-update` | | Pull the latest repository code before running |
| `--include-empty-targets`<br>`--show-all-targets`<br>`--complete-scan` | | Include hosts with empty scan results in the report |
| `--include-unreachable-targets` | | Include unreachable hosts in the report |
| `--smb-username` | | SMB username for authenticated SMB checks |
| `--smb-password` | | SMB password for authenticated SMB checks |
| `--smb-domain` | | SMB domain or workgroup for authentication |
| `--yes` | `-y` | Skip confirmation prompts (good for automation) |
| `--format` | `-f` | Report format: `html`, `pdf`, or `both` |

```bash
# See the full help at any time
recon-x --help
recon-x scan --help
```

#### Auto-update before scanning

If your RECON-X directory is a git clone, you can pull the latest updates automatically before starting a scan:

```bash
recon-x scan -t 192.168.1.100 --profile normal --auto-update
```

---

## 📊 Scan profiles explained

Choose your profile based on how thorough you need the scan to be:

| Profile | Speed | Depth | Best for |
|---|---|---|---|
| `quick` | ⚡ Fast | Top ports only | Quick spot checks, large ranges |
| `normal` | ⚖️ Balanced | Standard checks across all modules | Day-to-day audits |
| `full` | 🔬 Thorough | Deep checks, all ports, full analysis | Comprehensive security reviews |

**When in doubt, start with `normal`.** Use `quick` when scanning many hosts, and `full` when you need a detailed picture of a specific target.

---

## 🎯 Supported target formats

RECON-X accepts targets in any of these formats:

```
192.168.1.100               ← Single IP address
10.0.0.0/24                 ← CIDR range (entire subnet)
10.0.0.10-10.0.0.50         ← IP range
internal.example.com        ← Hostname
https://app.example.com     ← Full URL (triggers web checks)
```

---

## 📁 Understanding your output

After every scan, RECON-X creates a timestamped folder inside `output/`:

```
output/
└── scan_20240315_143022_MyTitle_a1b2c3d4/
    ├── report.html          ← Open this in a browser — interactive report
    ├── report.pdf           ← Print-ready version for sharing
    ├── checkpoint.json      ← Scan state (used for resuming interrupted scans)
    ├── cve_cache.json       ← Cached vulnerability data
    └── screenshots/         ← Browser screenshots of web targets
```

### What's in the report?

- **Executive summary** — overall risk score at a glance
- **Severity breakdown** — critical / high / medium / low finding counts
- **Per-host findings** — detailed results for every scanned target
- **Port & service map** — what's open and what's running
- **TLS details** — certificate info, expiry, cipher suites
- **Web security checks** — header analysis, clickjacking, banner exposure
- **Screenshot gallery** — visual evidence from web targets

---

## ⚙️ Configuration

Global defaults live in `config/settings.yaml`. You can edit this file to change how RECON-X behaves without having to pass flags every time.

Things you can configure:
- Default concurrency and timeouts
- Logging verbosity
- Screenshot capture settings
- CVE lookup behaviour

Open the file in any text editor — it's well-commented and easy to follow.

---

## 🔧 Troubleshooting

### `recon-x: command not found`

The virtual environment isn't active. Fix it:
```bash
source .venv/bin/activate
pip install -e .
```
Then try your command again.

---

### `Python version is too old` or version errors

You need Python 3.10 or newer. Check what you have:
```bash
python --version
```
Download the latest version from [python.org](https://python.org/downloads) and make sure it's the one your terminal uses.

---

### `nmap not found` or `nmap is not in PATH`

nmap needs to be installed *and* accessible from your terminal.

- **Linux:** `sudo apt-get install nmap`
- **macOS:** `brew install nmap`
- **Windows:** Install from [nmap.org](https://nmap.org), then **restart PowerShell**

Test with: `nmap --version`

---

### Screenshots are blank or failing

Chromium isn't installed properly. Fix it:

```bash
# Linux / macOS
.venv/bin/python -m playwright install chromium

# Windows
.venv\Scripts\python.exe -m playwright install chromium
```

---

### Report is empty or missing data

- Switch to a deeper profile: `--profile normal` or `--profile full`
- Remove any `--*-only` flags that might be restricting modules
- Check that your target is actually reachable: `ping <target>`

---

### Permission denied on setup scripts (Linux/macOS)

```bash
chmod +x setup.sh run.sh
```

---

### PowerShell won't run the setup script (Windows)

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup_windows.ps1
```

---

## 🔄 Keeping RECON-X updated

If you installed RECON-X from a git repository, update it like this:

```bash
git pull origin main
```

Then refresh your dependencies:
```bash
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

---

## ⚠️ Legal notice

> **Only scan systems you own or have explicit written authorization to test.**
>
> Unauthorized port scanning and network reconnaissance may violate computer fraud laws in your country, your organization's acceptable use policy, or both. RECON-X is a professional auditing tool — use it responsibly and ethically.

---

<div align="center">

*Built for security professionals. Use wisely.*

</div>