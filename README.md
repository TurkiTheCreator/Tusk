# TUSK ACT 1

```text
┌──────────────────── TUSK ACT 1 ────────────────────┐
│                                                     │
│          ★══════◎══════★                           │
│                                                     │
│    ________  _______ __ __                          │
│   /_  __/ / / / ___// //_/                          │
│    / / / / / /\__ \/ ,<                             │
│   / / / /_/ /___/ / /| |                            │
│  /_/  \____//____/_/ |_|                            │ 
│                                                     │
│             「Infinite Rotation」                   │
│                      CHUMIMI~IN                     │
│                                                     │
└─────────────────────────────────────────────────────┘
```

A lightweight vulnerability scanner written in Python.

Tusk is designed to perform fast reconnaissance and vulnerability assessment through port scanning, service detection, version fingerprinting, CPE generation, and CVE correlation.

The name Tusk was inspired by Tusk, the Stand of Johnny Joestar from JoJo's Bizarre Adventure: Steel Ball Run. The name also felt fitting for the project itself, as tusks are used to dig and uncover things—much like the tool is designed to dig through and gather information.

---

# Features

Current features include:

* TCP Port Scanning
* Multi-threaded scanning
* Banner Grabbing
* Service Detection
* Version Detection
* CPE Generation
* CVE Enumeration
* JSON Output Support
* Modular Architecture

---

# Installation

Clone the repository:

```bash
git clone https://github.com/TurkiTheCreator/Tusk.git

cd Tusk
```

Create a virtual environment:

```bash
python3 -m venv venv

source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Install Tusk:

```bash
pip install -e .
```

---

# Why use a virtual environment?

Using a virtual environment isolates project dependencies from the system Python installation.

Benefits include:

* Preventing package conflicts
* Easier development
* Safe dependency management
* Reproducible installations

Tusk can also be installed globally, but a virtual environment is recommended during development.

---

# Usage

Display the home screen:

```bash
tusk
```

Basic scan:

```bash
tusk scan -u example.com
```

Increase thread count:

```bash
tusk scan -u example.com -t 200
```

Scan specific ports:

```bash
tusk scan -u example.com -p 80,443
```

Top ports:

```bash
tusk scan -u example.com --top-ports 1000
```

Full scan:

```bash
tusk scan -u example.com --full
```

Save results:

```bash
tusk scan -u example.com --full -o output.json
```

---

# Example

Command:

```bash
tusk scan -u  example.com
```

Example output:

```text
[INF] Target: example.com

PORT      STATE SERVICE VERSION

22/tcp    open  ssh      OpenSSH 8.x
80/tcp    open  http     Apache 2.x
443/tcp   open  https    Apache 2.x

---------------------------------------------------------

[CPE]

80/tcp -> cpe:2.3:a:apache:http_server:2.x:*:*:*:*:*:*:*

---------------------------------------------------------

[VULN]

No vulnerabilities found.
```

---

# Project Structure

```text
Tusk/

├── cli.py

├── core/
│   ├── scanner.py
│   └── target.py

├── modules/
│   ├── ports.py
│   ├── banners.py
│   ├── versions.py
│   ├── cpe.py
│   └── cve_lookup.py

├── setup.py

├── requirements.txt

└── README.md
```

---

# Architecture

```text
Target
   ↓
Port Scan
   ↓
Banner Grabbing
   ↓
Version Detection
   ↓
CPE Generation
   ↓
CVE Correlation
   ↓
Results
```

---

# Upcoming Improvements

The following improvements are planned for the end of the week:

## CVE Lookup

* Improved CPE generation
* Better vulnerability matching
* CVSS score extraction
* Severity classification
* Caching to improve performance

## HTTP Analysis

* Security header analysis
* Missing header detection
* HTTPS support

## Technology Fingerprinting

* Web server detection
* Framework identification
* CMS detection

## SSL/TLS Inspection

* Certificate information
* Expiration checks
* TLS version detection

## Reporting

* Improved JSON export
* HTML reports
* PDF reports

## Performance

* Faster port scanning
* Reduced timeouts
* Better thread management
* Parallel version detection

## User Experience

* Progress bars
* Colored output
* Rich tables
* Better formatting

---

# Roadmap

Future versions may include:

* Async scanning
* Directory discovery
* Subdomain enumeration
* WordPress detection
* Joomla detection
* HTTP header analysis
* WAF detection
* Docker support
* PyPI distribution
* Kali package support

---

# Disclaimer

Tusk is intended for educational purposes and authorized security assessments only.

Users are responsible for ensuring they have permission to scan target systems.

Unauthorized use against systems without permission is prohibited.

---

# Author

GitHub:

https://github.com/TurkiTheCreator

---
