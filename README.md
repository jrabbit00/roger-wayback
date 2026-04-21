# Roger Wayback 🐰

Wayback Machine scanner for bug bounty hunting. Discovers archived pages, old endpoints, and historical URLs that might reveal vulnerabilities.

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

## License

MIT License