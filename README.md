<p align="center">
  <img src="icon.png" width="140" alt="DockerScan logo">
</p>

<h1 align="center">DockerScan</h1>

<p align="center"><strong>See Through Docker Images.</strong></p>

<p align="center">An Offline Docker Image Security Scanner for Windows — Desktop GUI & CLI</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6" alt="Platform">
  <img src="https://img.shields.io/badge/Version-2.0-8A2BE2" alt="Version">
  <img src="https://img.shields.io/badge/Language-Python-3776AB" alt="Language">
  <img src="https://img.shields.io/badge/Interface-CustomTkinter-orange" alt="Interface">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
</p>

<p align="center">🚀 Built by <strong>Muhammad Abdul Rehman</strong> · ⚡ Stay Curious, Stay Secure</p>
DockerScan inspects Docker `docker save` archives and unpacked image filesystems without starting containers. It checks image contents for likely secrets, package vulnerabilities from a local JSON database, and selected Docker/image configuration risks.
> **Project status:** Independent security-learning project. Findings are heuristic and should be validated before making production decisions. The bundled vulnerability database is a small sample, not a complete or continuously updated CVE feed.
Highlights
Offline scanning: no Docker daemon or running container is required.
Desktop interface: CustomTkinter dashboard, findings, package inventory, image layers, scan history, and report comparison.
CLI: suitable for repeatable local checks and scripts.
Secret detection: pattern and entropy-based checks, with detected values redacted in reports.
Package inventory: supports dpkg, apk, RPM SQLite databases, and Python `dist-info` metadata.
Local vulnerability matching: compares detected package versions against the supplied JSON database.
Configuration checks: selected checks for root users, exposed sensitive ports, missing health checks, setuid/setgid files, and risky build commands.
Layer attribution: associates supported findings with the image layer that introduced them.
Allowlisting and report diffing: document accepted findings and compare JSON reports across scans.
## Screenshots
![DockerScan dashboard](Screenshot%202026-11-25%20163707.png)
Requirements
Python 3.9 or newer
Windows for the supplied `.bat` launchers
`customtkinter` for the desktop GUI
The scanner and CLI use Python standard-library modules. The GUI dependency is listed in `requirements.txt`.
Quick start (Windows)
Install Python from python.org. During setup, enable Add Python to PATH.
Download or clone this repository.
Open a terminal in the repository folder.
Install the dependency:
```powershell
   py -m pip install -r requirements.txt
   ```
Start the desktop application:
```powershell
   py main.py
   ```
Or double-click `RUN_DESKTOP.bat`.
Run from source (Linux / macOS)
The CLI can be run on platforms with Python 3.9+:
```bash
python3 -m pip install -r requirements.txt
python3 cli.py scan sample_vulnerable_image.tar
```
The desktop interface requires a working Tk installation and a supported graphical environment.
CLI usage
Scan a Docker image archive:
```bash
python cli.py scan path/to/image.tar
```
Scan an unpacked Docker image directory:
```bash
python cli.py scan path/to/unpacked-image/
```
Scan a plain filesystem directory with an image configuration file:
```bash
python cli.py scan path/to/rootfs/ --config sample_config.json
```
Use a custom vulnerability database and allowlist:
```bash
python cli.py scan image.tar \
  --db data/vulnerabilities.json \
  --allowlist allowlist.example.json \
  --fail-on High
```
Export reports:
```bash
python cli.py scan image.tar --out report.txt --json report.json
```
Compare two JSON reports:
```bash
python cli.py diff before.json after.json --out comparison.txt
```
See all available options:
```bash
python cli.py --help
python cli.py scan --help
python cli.py diff --help
```
Exit codes
Code	Meaning
`0`	Scan completed; no finding reached the configured failure threshold (or no threshold was set).
`1`	A finding reached `--fail-on`, or diff mode found new findings.
`2`	Input, parsing, or report-writing error.
Try the included sample images
The repository includes small demonstration archives:
`sample_vulnerable_image.tar`
`sample_vulnerable_image_fixed.tar`
`sample_rpm_image.tar`
Run a sample scan:
```bash
python cli.py scan sample_vulnerable_image.tar
```
Compare the vulnerable and fixed examples:
```bash
python cli.py scan sample_vulnerable_image.tar --json before.json
python cli.py scan sample_vulnerable_image_fixed.tar --json after.json
python cli.py diff before.json after.json
```
These are test fixtures for demonstrating scanner behavior. They are not real production images.
Allowlist example
Copy `allowlist.example.json` and edit it for your environment. Rules can match fields such as path, title, category, severity, package, pattern, or finding fingerprint. A rule's `reason` documents why the finding is accepted.
Example:
```json
{
  "rules": [
    {
      "path": "/app/.env.example",
      "reason": "Example configuration file"
    }
  ]
}
```
Review allowlist rules periodically. Suppressing a finding does not remove the underlying risk.
Vulnerability database
The default database is `data/vulnerabilities.json`. It uses a local JSON format containing package names, ecosystems, vulnerability IDs, severities, fixed versions, and descriptions.
Important: The bundled database is deliberately limited and is not an authoritative vulnerability feed. It can miss vulnerabilities and may report false positives, particularly where distributions backport security fixes. Keep your own database current and verify findings against vendor advisories and trusted vulnerability sources.
Build a Windows executable
On Windows, run:
```powershell
BUILD_EXE.bat
```
The script uses the included PyInstaller spec files. Generated `build/` and `dist/` directories are intentionally excluded from source control; publish release executables through GitHub Releases if you choose to distribute them.
Repository structure
```text
DockerScan/
├── data/
│   └── vulnerabilities.json
├── allowlist.example.json
├── allowlist.py
├── cli.py
├── config_checker.py
├── desktop_app.py
├── main.py
├── report_generator.py
├── scanner.py
├── secret_detector.py
├── vulnerability_checker.py
├── requirements.txt
├── RUN_DESKTOP.bat
├── BUILD_EXE.bat
├── DockerScan.spec
├── DockerScan-cli.spec
└── sample_*.tar
```
Security and safe use
DockerScan is a static inspection tool. It is designed to read image data, not run containers or execute image commands.
Only scan images and files you are authorized to inspect.
Treat reports as potentially sensitive: they can reveal package inventories, file paths, and security findings. Store and share them carefully.
Secret detection is heuristic. False positives and false negatives are possible.
A clean scan does not prove an image is secure.
Validate important findings independently before blocking a release or changing a production system.
For vulnerability reports or security concerns in this project, please do not publish real secrets or sensitive image contents in a public issue.
Known limitations
The RPM parser currently supports the SQLite `rpmdb.sqlite` format; older RPM database formats may not be supported.
The bundled vulnerability database is only a sample and is not updated automatically.
Version comparison is an approximation and may not account for distribution-specific backported fixes.
OCI image layouts without a Docker `manifest.json`, and some package ecosystems (including Java and npm inventories), are not currently covered.
Scanning a plain filesystem folder on Windows cannot reliably inspect Unix setuid bits; scanning a tar archive is preferred for that check.
Windows-specific path edge cases should be tested on the target Windows version before relying on results operationally.
Contributing
Bug reports, reproducible test cases, and focused improvements are welcome. See CONTRIBUTING.md.
License
This project is released under the MIT License. See LICENSE.
