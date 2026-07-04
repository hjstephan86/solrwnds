# Solarwinds - Log Analysis Tool

Professional tool for log analysis of Solarwinds

## Modules

### Access-Logs Analysis

Professional Python-based analysis of Heroku Router logs with geolocation, VPN detection, and bot identification for https://www.123-bibel.de.

**Features:**
- HTTP request extraction from gzip-compressed logs
- IP geolocation with 14+ known hosting providers
- VPN detection (Mullvad, Linode, etc.)
- Bot/Crawler identification (Google, Microsoft, AWS)
- CSV & HTML exports

**Quick Start:**
```bash
python3 analyze-access-logs.py -d /path/to/logs \
  --csv results.csv \
  --html report.html
```

**Requirements:**
- Python 3.7+
- No external dependencies (only Standard Library)

---

## Tools Overview

| Tool | Purpose | Status |
|------|---------|--------|
| `analyze-access-logs.py` | Heroku log analysis | Production-ready |

## Technology Stack

- **Language:** Python 3.7+
- **Standard Libraries:** gzip, json, re, argparse, pathlib, collections
- **Zero external dependencies** - completely self-contained

## Getting Started

1. **Clone the repository:**
   ```bash
   git clone https://github.com/hjstephan86/solrwinds.git
   cd solrwinds
   ```

2. **Analyze logs:**
   ```bash
   python3 analyze-access-logs.py -d logs
   ```

## Requirements

- **Python 3.7+** (no virtual environment needed)
- **Linux/macOS/Windows** (all platforms supported)
- **No external packages** required

## Author

**Stephan Epp** - Senior Software Developer

- GitHub: https://github.com/hjstephan86
- Email: hjstephan86@gmail.com
- Portfolio: https://github.com/hjstephan86/science (220+ research papers)

## Other Projects

- **pyble**: FastAPI-based Bible Study App
- **JuraX**: Jakarta EE Legal Case Management System
- **Science**: 220+ academic papers on graph theory, cryptography, embedded systems, etc.

## Quick Links

- Repository: https://github.com/hjstephan86/solrwinds
- License: https://github.com/hjstephan86/solrwinds/blob/main/LICENSE
- Issues: https://github.com/hjstephan86/solrwinds/issues
