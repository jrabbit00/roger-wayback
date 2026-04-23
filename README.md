# Roger Wayback 🐰

[![Python 3.7+](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Wayback Machine scanner for bug bounty hunting.**

Discovers archived pages, old endpoints, deprecated APIs, backup files, and historical URLs that might reveal vulnerabilities.

Part of the [Roger Toolkit](https://github.com/jrabbit00/roger-recon) - 14 free security tools for bug bounty hunters.

🔥 **[Get the complete toolkit on Gumroad](https://jrabbit00.gumroad.com)**

## Why Wayback?

The Wayback Machine archives billions of web pages. Hidden gems include:
- Old API endpoints no longer linked
- Debug/admin pages that existed before
- Backup files and configs
- Deprecated but vulnerable paths
- Parameter patterns from older versions

## Features

- Query Wayback Machine API for target
- Extract all archived URLs
- Filter by file extensions
- Find hidden parameters from historical data
- Analyze URL patterns
- Extract JavaScript files from archives
- Multi-threaded processing

## Installation

```bash
git clone https://github.com/jrabbit00/roger-wayback.git
cd roger-wayback
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python3 wayback.py target.com

# Filter by extensions
python3 wayback.py target.com -e php,js,bak

# Find only endpoints
python3 wayback.py target.com --endpoints

# Save results
python3 wayback.py target.com -o findings.txt
```

## Options

| Flag | Description |
|------|-------------|
| `-e, --extensions` | Filter by extensions (comma-separated) |
| `-E, --endpoints` | Only show API endpoints |
| `-t, --threads` | Number of threads (default: 10) |
| `-d, --depth` | Max results to fetch (default: 1000) |
| `-q, --quiet` | Quiet mode |
| `-o, --output` | Output results to file |

## What It Finds

- Old admin panels
- Deprecated API endpoints
- Backup files (`.bak`, `.old`, `.backup`)
- Source code exposures
- Debug endpoints
- Hidden parameters from historical data

## Examples

```bash
# Full scan
python3 wayback.py example.com

# Find old PHP files
python3 wayback.py example.com -e php

# Extract only API endpoints
python3 wayback.py example.com -E

# Save everything
python3 wayback.py example.com -o wayback_results.txt
```

## 🐰 Part of the Roger Toolkit

| Tool | Purpose |
|------|---------|
| [roger-recon](https://github.com/jrabbit00/roger-recon) | All-in-one recon suite |
| [roger-direnum](https://github.com/jrabbit00/roger-direnum) | Directory enumeration |
| [roger-jsgrab](https://github.com/jrabbit00/roger-jsgrab) | JavaScript analysis |
| [roger-sourcemap](https://github.com/jrabbit00/roger-sourcemap) | Source map extraction |
| [roger-paramfind](https://github.com/jrabbit00/roger-paramfind) | Parameter discovery |
| [roger-wayback](https://github.com/jrabbit00/roger-wayback) | Wayback URL enumeration |
| [roger-cors](https://github.com/jrabbit00/roger-cors) | CORS misconfigurations |
| [roger-jwt](https://github.com/jrabbit00/roger-jwt) | JWT security testing |
| [roger-headers](https://github.com/jrabbit00/roger-headers) | Security header scanner |
| [roger-xss](https://github.com/jrabbit00/roger-xss) | XSS vulnerability scanner |
| [roger-sqli](https://github.com/jrabbit00/roger-sqli) | SQL injection scanner |
| [roger-redirect](https://github.com/jrabbit00/roger-redirect) | Open redirect finder |
| [roger-idor](https://github.com/jrabbit00/roger-idor) | IDOR detection |
| [roger-ssrf](https://github.com/jrabbit00/roger-ssrf) | SSRF vulnerability scanner |

## ☕ Support

If Roger Wayback helps you find vulnerabilities, consider [supporting the project](https://github.com/sponsors/jrabbit00)!

## License

MIT License - Created by [Ashlee (Jessica Rabbit)](https://github.com/jrabbit00)