# The Open OSINT Board

A fully self-hostable, browser-based threat intelligence dashboard with a
live Python backend proxy that pulls from **9 real public OSINT feeds**.

---

## Quick Start

```bash
# 1. Make startup script executable
chmod +x start.sh

# 2. Run The Open OSINT Board
./start.sh
```

The script will:
- Install Python dependencies automatically
- Start the backend proxy on **port 5000**
- Open the dashboard in your browser

---

## Manual Start

```bash
# Install deps once
pip3 install flask flask-cors requests apscheduler

# Start backend
cd backend
python3 server.py

# Open frontend in browser (new tab)
open frontend/index.html          # macOS
xdg-open frontend/index.html     # Linux
start frontend/index.html         # Windows
```

---

## Architecture

```
toob/
├── backend/
│   ├── server.py          ← Flask proxy server (port 5000)
│   └── requirements.txt
├── frontend/
│   └── index.html         ← Single-file dashboard (open in browser)
├── data/                  ← Cache dir (auto-created)
└── start.sh               ← One-command launcher
```

The frontend talks to the backend via `http://localhost:5000/api/*`.
All OSINT API calls are made server-side (avoids browser CORS restrictions).

---

## Live Data Sources & Refresh Schedule

| Feed | Source | Data | Refresh |
|------|--------|------|---------|
| MalwareBazaar | abuse.ch | Recent malware samples (SHA256, family, tags) | **10 min** |
| URLhaus | abuse.ch | Malicious URLs actively distributing malware | **10 min** |
| ThreatFox | abuse.ch | IOCs (C2 IPs, domains, hashes) with malware tags | **15 min** |
| Feodo Tracker | abuse.ch | Botnet C2 IP blocklist (Emotet, QBot, etc.) | **30 min** |
| SSL Blacklist | abuse.ch | Malicious SSL certificate SHA1 hashes | **30 min** |
| PhishTank | phishtank.org | Verified phishing URLs | **60 min** |
| NVD / NIST | nvd.nist.gov | Critical CVEs published in last 30 days | **2 hours** |
| CISA KEV | cisa.gov | Known Exploited Vulnerabilities catalog | **6 hours** |
| MITRE ATT&CK | github.com/mitre/cti | Full enterprise technique/tactic database | **24 hours** |

All feeds are **free, no API key required**.

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/status` | Health check — all feed statuses and record counts |
| `GET /api/iocs` | Aggregated IOCs (ThreatFox + Feodo + URLhaus) |
| `GET /api/malware` | MalwareBazaar recent samples |
| `GET /api/vulns` | Combined CISA KEV + NVD critical CVEs |
| `GET /api/phishing` | PhishTank verified phishing URLs |
| `GET /api/mitre?tactic=X&q=Y` | MITRE ATT&CK techniques (filterable) |
| `GET /api/stream` | Unified event stream across all feeds |
| `GET /api/feed/<name>` | Raw feed data for any specific source |
| `POST /api/refresh/<name>` | Manually trigger a feed refresh |
| `GET /api/layout` | Retrieve saved dashboard layout for authenticated user |
| `POST /api/layout` | Save dashboard layout for authenticated user |

---

## What's Live vs Static

### ✅ Fully Live (auto-refreshed)
- **IOCs** — ThreatFox C2s, Feodo botnet IPs, URLhaus malicious URLs
- **Malware Samples** — MalwareBazaar with family/hash/tag data
- **Phishing URLs** — PhishTank verified entries
- **Vulnerabilities** — CISA KEV (all known exploited) + NVD critical CVEs
- **MITRE ATT&CK** — Full enterprise technique database
- **SSL Blacklist** — Malicious certificate hashes
- **Activity Stream** — Unified event feed across all sources

### ⚠️ Static / Curated
- **Threat Actors** — No free machine-readable API exists for attributed actor data.
  *Workaround options:* MISP, OpenCTI, paid feeds (Recorded Future, Mandiant, etc.)
  The Open OSINT Board cross-references live ThreatFox IOCs against actor malware families automatically.

- **Campaigns** — No public structured campaign feed.
  *Workaround:* MISP events, manual entry, or OSINT from threat reports.

- **Cases / Reports** — Intentionally internal. Your own workflow data.

- **CVSS scores for CISA KEV entries** — The KEV feed doesn't include CVSS.
  NVD API is queried separately for scoring; overlap is matched by CVE ID.

---

## Configuration

In the dashboard → **Settings → Backend Connection**, you can change the backend URL
if you're running The Open OSINT Board on a remote server (e.g., `http://192.168.1.100:5000`).

The setting persists in `localStorage`.

---

## Expanding with Paid / Premium Feeds

To add more actors/campaigns with live data, these APIs can be integrated:

| Service | What it adds | Cost |
|---------|-------------|------|
| **MISP** (self-hosted) | Shared threat intel events, actors, campaigns | Free (self-host) |
| **OTX AlienVault** | Pulses, actor profiles, structured IOCs | Free (API key) |
| **VirusTotal** | File/URL/IP reputation enrichment | Free tier (API key) |
| **Shodan** | Host exposure, open ports on IOC IPs | Free tier (API key) |
| **Recorded Future** | Actor intel, campaign tracking | Paid |
| **Mandiant Advantage** | Premium APT actor profiles | Paid |

To add OTX (free), create `/backend/feeds/otx.py` and call:
`https://otx.alienvault.com/api/v1/pulses/subscribed` with your API key header.

---

## Requirements

- Python 3.9+
- Modern browser (Chrome, Firefox, Edge)
- Internet connection (for API calls)
- Ports: 5000 (backend)

---

## Security Notes

- The backend runs locally — never expose port 5000 to the internet without auth
- All API calls are outbound-only (no inbound data accepted from external sources)
- Feed data is held in-memory; only dashboard layouts and user accounts are written to disk
- Dashboard layouts are saved per-user in `backend/data/layouts/` on the server
- User accounts and session tokens are stored in `backend/data/`
- Custom IOCs, watchlists, cases, campaigns, and reports persist in browser localStorage
