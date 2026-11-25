<div align="center">
<img src="icon.png" width="120" alt="DockerScan logo"/>
🛡️ DockerScan
Offline Docker Image Security Scanner — Desktop GUI + CLI
!Python
!Platform
!GUI
!Mode
!License
🚀 Built by Muhammad Abdul Rehman
BS Computer Science — Virtual University of Pakistan · PNY Trainings
⚡ Stay Curious, Stay Secure
</div>

📌 About
DockerScan is a security scanner that checks Docker images without running them. It opens a saved Docker image (.tar file) or an unpacked image folder and looks for security problems — completely offline, no Docker installation and no internet needed.
It was built as a final project for the PNY Trainings Cyber Security course.
✨ Features — The 5 Security Checks
#
Check
What it finds
1
🔑 Secret Detection
Hardcoded passwords, API keys, tokens and private keys hidden in files (pattern + entropy based, values redacted in reports)
2
📦 Vulnerable Packages
Installed packages (dpkg, apk, RPM, Python) matched against a local vulnerability database (JSON)
3
⚙️ Configuration Risks
Container running as root, sensitive exposed ports (22, 3306…), missing HEALTHCHECK, secrets in ENV
4
⚠️ Dangerous File Permissions
setuid / setgid files that can be abused for privilege escalation
5
🧱 Layer-by-Layer Analysis
Which image layer introduced each problem, plus full package inventory
More: severity dashboard (Critical / High / Medium / Low), search & filters, scan history, report comparison (diff), allowlist support, and one-click TXT / JSON report export.
📸 Screenshot
!DockerScan dashboard
🚀 Quick Start (Windows)
:: 1. Install Python 3.9+ from python.org (tick "Add Python to PATH")
:: 2. Install the one dependency
py -m pip install -r requirements.txt

:: 3. Run the desktop app — or just double-click RUN_DESKTOP.bat
py main.py
Build a single clickable .exe: double-click BUILD_EXE.bat → your app appears in the dist folder.
🧪 Try the Demo
The repo includes sample images so you can test instantly:
Open the app → Select Image
Pick sample_vulnerable_image.tar
Click Start Scan
Result: 24 findings — 8 Critical · 6 High · 7 Medium · 2 Low · 1 Informational ✅
Then scan sample_vulnerable_image_fixed.tar and use Diff to see the problems disappear.
💻 CLI Usage
python cli.py scan sample_vulnerable_image.tar
python cli.py scan image.tar --out report.txt --json report.json
python cli.py diff before.json after.json
📁 Project Structure
DockerScan/
├── main.py                    → App entry point
├── desktop_app.py             → Desktop GUI (CustomTkinter)
├── scanner.py                 → Core scanning engine
├── secret_detector.py         → Check 1: secrets
├── vulnerability_checker.py   → Check 2: vulnerable packages
├── config_checker.py          → Checks 3–5: config, permissions, layers
├── report_generator.py        → TXT / JSON reports
├── cli.py                     → Command-line interface
├── data/vulnerabilities.json  → Local vulnerability database
└── sample_*.tar               → Demo images (vulnerable + fixed)
⚠️ Limitations
Static scan only — the container is never run.
The bundled vulnerability database is a small sample for learning, not a full CVE feed.
Always verify important findings before using them in production.
👨‍💻 Author
<div align="center">
Made by Abdul Rehman
Muhammad Abdul Rehman — BS CS, Virtual University of Pakistan · PNY Trainings
🛡️ DockerScan · ⚡ Stay Curious, Stay Secure
</div>
📄 License
Released under the MIT License — see LICENSE.
