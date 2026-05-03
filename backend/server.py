"""
The Open OSINT Board — Backend Proxy Server v2.2
====================================
abuse.ch (MalwareBazaar, ThreatFox, URLhaus) and OpenPhish all now
require registration or block unauthenticated requests entirely.

Strategy for each feed:
  MalwareBazaar  → requires free API key (abuse.ch account)
  ThreatFox      → requires free API key (abuse.ch account)
  URLhaus        → requires free API key (abuse.ch account)
  OpenPhish      → blocked without key
  MITRE ATT&CK   → GitHub rate limits raw access; use jsDelivr CDN mirror
  CISA KEV       → works fine, no key
  Feodo Tracker  → works fine, no key (different abuse.ch endpoint)
  SSL Blacklist  → works fine, no key (CSV download)
  NVD/NIST       → works fine, no key (optional key for higher rate limit)

All abuse.ch keys are FREE — register once at:
  https://abuse.ch/login (one account covers all services)
Then find your API key at each service dashboard.

Config: edit backend/config.json to add your keys.
The server checks every startup and uses keys when present.
"""

import csv
import json
import logging
import re
import time
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request
import hashlib, hmac, os, secrets
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("toob")

# ── Config / API Keys ─────────────────────────────────────────────────────────
CONFIG_FILE = Path(__file__).parent / "config.json"
CONFIG = {
    "MALWAREBAZAAR_API_KEY": "",
    "THREATFOX_API_KEY":     "",
    "URLHAUS_API_KEY":       "",
    "NVD_API_KEY":           "",
    "ABUSEIPDB_API_KEY":     "",   # free at abuseipdb.com
    "ROAD511_API_KEY":       "",   # road511.com — cameras for NY/NJ/TX/OH/PA + 40 states
}
if CONFIG_FILE.exists():
    try:
        CONFIG.update(json.loads(CONFIG_FILE.read_text()))
        log.info("Loaded config.json")
    except Exception as e:
        log.warning(f"config.json load error: {e}")

def save_config():
    CONFIG_FILE.write_text(json.dumps(CONFIG, indent=2))

DATA_DIR   = Path(__file__).parent / "data"   # backend/data/
DATA_DIR.mkdir(exist_ok=True)
USERS_FILE = DATA_DIR / "users.json"
TOKEN_FILE = DATA_DIR / "tokens.json"

TIMEOUT = 25

def hdrs(extra=None):
    h = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
         "Accept": "application/json, text/plain, */*"}
    if extra:
        h.update(extra)
    return h

def get(url, timeout=TIMEOUT, extra_headers=None, **kw):
    try:
        r = requests.get(url, headers=hdrs(extra_headers), timeout=timeout, **kw)
        r.raise_for_status()
        return r
    except Exception as e:
        log.warning(f"GET {url[:80]} → {e}")
        return None

def post(url, data=None, json_body=None, extra=None, timeout=TIMEOUT, **kw):
    try:
        r = requests.post(url, headers=hdrs(extra), data=data, json=json_body,
                          timeout=timeout, **kw)
        r.raise_for_status()
        return r
    except Exception as e:
        log.warning(f"POST {url[:80]} → {e}")
        return None

# ── Cache ─────────────────────────────────────────────────────────────────────
FEEDS = ["malware_bazaar","urlhaus","threatfox","cisa_kev","feodo",
         "ssl_blacklist","nvd_cves","mitre_attack","openphish",
         "blocklist_de","dshield","ipsum","cinsscore","abuseipdb"]

cache = {k: {"data":[], "updated":None, "status":"pending", "count":0,
             "note":""} for k in FEEDS}
lock  = threading.Lock()

def set_cache(key, data, status="ok", note=""):
    with lock:
        cache[key].update(data=data, status=status, note=note,
                          updated=datetime.now(timezone.utc).isoformat(),
                          count=len(data) if isinstance(data, list) else 1)
    log.info(f"[{key}] {cache[key]['count']} records — {status}"
             + (f" ({note})" if note else ""))

def get_cache(key):
    with lock:
        return dict(cache[key])

# ══════════════════════════════════════════════════════════════════════════════
# FETCHERS
# ══════════════════════════════════════════════════════════════════════════════

def _clean_key(key):
    """Strip whitespace, newlines, and any non-printable characters from API key."""
    return re.sub(r'\s+', '', (key or "")).strip()


def fetch_malware_bazaar():
    log.info("[malware_bazaar] Fetching...")
    key = _clean_key(CONFIG.get("MALWAREBAZAAR_API_KEY",""))

    if key:
        log.info(f"[malware_bazaar] Using key (len={len(key)}, prefix={key[:4]}...)")
        r = post("https://mb-api.abuse.ch/api/v1/",
                 data={"query":"get_recent","selector":"100"},
                 extra={"Auth-Key": key})  # MalwareBazaar uses Auth-Key, not API-KEY
        if r:
            try:
                body = r.json()
                log.info(f"[malware_bazaar] query_status={body.get('query_status')}")
                samples = body.get("data") or []
                if samples:
                    set_cache("malware_bazaar", _norm_mb(samples), note="API key")
                    return
                elif body.get("query_status") not in ("unauthorized", "no_auth"):
                    set_cache("malware_bazaar", [], "ok", note="No recent samples")
                    return
            except Exception as e:
                log.error(f"[malware_bazaar] parse: {e}")
    else:
        log.warning("[malware_bazaar] No API key in config")

    set_cache("malware_bazaar", [], "needs_key",
              note="Requires free API key — see backend/config.json")

def _norm_mb(samples):
    out = []
    for s in samples:
        out.append({
            "sha256":    s.get("sha256_hash",""),
            "md5":       s.get("md5_hash",""),
            "file_name": s.get("file_name",""),
            "file_type": s.get("file_type",""),
            "file_size": s.get("file_size",0),
            "signature": s.get("signature") or "Unknown",
            "tags":      s.get("tags") or [],
            "first_seen":s.get("first_seen",""),
            "reporter":  s.get("reporter",""),
            "comment":   s.get("comment",""),
            "source":    "MalwareBazaar",
        })
    return out


def fetch_urlhaus():
    log.info("[urlhaus] Fetching...")
    key = CONFIG.get("URLHAUS_API_KEY","").strip()

    if key:
        # URLhaus API now uses GET with Auth-Key header
        r = get("https://urlhaus-api.abuse.ch/v1/urls/recent/",
                extra_headers={"Auth-Key": key})
        if r:
            try:
                body = r.json()
                urls = body.get("urls",[])
                if urls:
                    set_cache("urlhaus", _norm_uh(urls), note="API key")
                    return
            except Exception as e:
                log.error(f"[urlhaus] parse: {e}")

    set_cache("urlhaus", [], "needs_key",
              note="Requires free API key — see backend/config.json")

def _norm_uh(urls):
    out = []
    for u in urls:
        out.append({
            "url":       u.get("url",""),
            "url_status":u.get("url_status",""),
            "host":      u.get("host",""),
            "date_added":u.get("date_added",""),
            "threat":    u.get("threat",""),
            "tags":      u.get("tags") or [],
            "reporter":  u.get("reporter",""),
            "source":    "URLhaus",
        })
    return out


def fetch_threatfox():
    log.info("[threatfox] Fetching...")
    key = _clean_key(CONFIG.get("THREATFOX_API_KEY",""))

    if key:
        log.info(f"[threatfox] Using key (len={len(key)}, prefix={key[:4]}...)")
        r = post("https://threatfox-api.abuse.ch/api/v1/",
                 json_body={"query":"get_iocs","days":3},
                 extra={"Auth-Key": key})  # ThreatFox uses Auth-Key
        if r:
            try:
                body = r.json()
                log.info(f"[threatfox] query_status={body.get('query_status')}")
                iocs = body.get("data") or []
                if iocs:
                    set_cache("threatfox", _norm_tf(iocs), note="API key")
                    return
                elif body.get("query_status") not in ("unauthorized", "no_auth"):
                    set_cache("threatfox", [], "ok", note="No recent IOCs")
                    return
            except Exception as e:
                log.error(f"[threatfox] parse: {e}")

    set_cache("threatfox", [], "needs_key",
              note="Requires free API key — see backend/config.json")

def _norm_tf(iocs):
    out = []
    for i in iocs:
        out.append({
            "id":            i.get("id",""),
            "ioc":           i.get("ioc",""),
            "ioc_type":      i.get("ioc_type",""),
            "ioc_type_desc": i.get("ioc_type_desc",""),
            "threat_type":   i.get("threat_type",""),
            "malware":       i.get("malware",""),
            "malware_alias": i.get("malware_alias",""),
            "confidence":    i.get("confidence_level",0),
            "first_seen":    i.get("first_seen",""),
            "last_seen":     i.get("last_seen",""),
            "reporter":      i.get("reporter",""),
            "tags":          i.get("tags") or [],
            "reference":     i.get("reference",""),
            "source":        "ThreatFox",
        })
    return out


def fetch_cisa_kev():
    log.info("[cisa_kev] Fetching...")
    r = get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    if not r:
        set_cache("cisa_kev", cache["cisa_kev"]["data"] or [], "error")
        return
    try:
        vulns = r.json().get("vulnerabilities",[])
        vulns.sort(key=lambda x: x.get("dateAdded",""), reverse=True)
        out = []
        for v in vulns:
            out.append({
                "cve_id":          v.get("cveID",""),
                "vendor":          v.get("vendorProject",""),
                "product":         v.get("product",""),
                "name":            v.get("vulnerabilityName",""),
                "date_added":      v.get("dateAdded",""),
                "short_desc":      v.get("shortDescription",""),
                "action":          v.get("requiredAction",""),
                "due_date":        v.get("dueDate",""),
                "known_ransomware":v.get("knownRansomwareCampaignUse","Unknown"),
                "notes":           v.get("notes",""),
                "source":          "CISA KEV",
            })
        set_cache("cisa_kev", out)
    except Exception as e:
        log.error(f"[cisa_kev] {e}")
        set_cache("cisa_kev", [], "error")


def fetch_feodo():
    log.info("[feodo] Fetching...")
    r = get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    if not r:
        set_cache("feodo", cache["feodo"]["data"] or [], "error")
        return
    try:
        out = []
        for e in r.json():
            out.append({
                "ip":         e.get("ip_address",""),
                "port":       e.get("port",""),
                "status":     e.get("status",""),
                "malware":    e.get("malware",""),
                "first_seen": e.get("first_seen",""),
                "last_online":e.get("last_online",""),
                "country":    e.get("country",""),
                "hostname":   e.get("hostname",""),
                "as_number":  e.get("as_number",""),
                "as_name":    e.get("as_name",""),
                "source":     "Feodo Tracker",
            })
        set_cache("feodo", out)
    except Exception as e:
        log.error(f"[feodo] {e}")
        set_cache("feodo", [], "error")


def fetch_ssl_blacklist():
    log.info("[ssl_blacklist] Fetching...")
    r = get("https://sslbl.abuse.ch/blacklist/sslblacklist.csv")
    if not r:
        set_cache("ssl_blacklist", cache["ssl_blacklist"]["data"] or [], "error")
        return
    try:
        lines = [l for l in r.text.splitlines() if l and not l.startswith("#")]
        out   = []
        for line in lines[:300]:
            parts = line.split(",")
            if len(parts) >= 3:
                out.append({"listed":parts[0].strip(),"sha1":parts[1].strip(),
                            "reason":parts[2].strip(),"source":"SSL Blacklist"})
        set_cache("ssl_blacklist", out)
    except Exception as e:
        log.error(f"[ssl_blacklist] {e}")
        set_cache("ssl_blacklist", [], "error")


def fetch_nvd_cves():
    log.info("[nvd_cves] Fetching...")
    end   = datetime.now(timezone.utc)
    start = end - timedelta(days=30)

    # NVD API key goes in the HEADER, not the URL params
    extra_hdrs = {}
    nvd_key = CONFIG.get("NVD_API_KEY","").strip()
    if nvd_key:
        extra_hdrs["apiKey"] = nvd_key
        log.info(f"[nvd_cves] Using API key (prefix={nvd_key[:8]}...)")

    # Attempt 1: with date range
    params = {
        "cvssV3Severity":  "CRITICAL",
        "resultsPerPage":  100,
        "pubStartDate":    start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":      end.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }
    r = get("https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params, extra_headers=extra_hdrs)

    # Attempt 2: without date range
    if not r:
        log.warning("[nvd_cves] Attempt 1 failed, retrying without date filter...")
        time.sleep(2)
        r = get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cvssV3Severity": "CRITICAL", "resultsPerPage": 50},
                extra_headers=extra_hdrs)

    if not r:
        log.error("[nvd_cves] All attempts failed")
        set_cache("nvd_cves", cache["nvd_cves"]["data"] or [], "error",
                  note="NVD API unreachable — check your NVD API key")
        return

    try:
        items = r.json().get("vulnerabilities", [])
        out   = []
        for item in items:
            cve      = item.get("cve", {})
            metrics  = cve.get("metrics", {})
            cvss     = {}
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metrics.get(key):
                    cvss = metrics[key][0].get("cvssData", {})
                    break
            desc_en = next((d["value"] for d in cve.get("descriptions", [])
                            if d.get("lang") == "en"), "")
            out.append({
                "cve_id":        cve.get("id", ""),
                "description":   desc_en[:400],
                "cvss_score":    cvss.get("baseScore", 0),
                "cvss_vector":   cvss.get("vectorString", ""),
                "severity":      cvss.get("baseSeverity", ""),
                "published":     cve.get("published", "")[:10],
                "last_modified": cve.get("lastModified", "")[:10],
                "weaknesses":    [d.get("value","") for w in cve.get("weaknesses",[])
                                  for d in w.get("description",[]) if d.get("lang")=="en"],
                "references":    [ref.get("url","") for ref in cve.get("references",[])[:3]],
                "source":        "NVD/NIST",
            })
        set_cache("nvd_cves", out)
        log.info(f"[nvd_cves] {len(out)} CVEs loaded")
    except Exception as e:
        log.error(f"[nvd_cves] parse error: {e}")
        set_cache("nvd_cves", [], "error")


def fetch_mitre_attack():
    """
    MITRE ATT&CK techniques.

    The full STIX bundle (~10MB) times out on many connections.
    Instead we use the MITRE ATT&CK Navigator layer index which lists
    all techniques in a compact format, then fall back to a curated
    hardcoded set so the page always has data.

    Sources tried in order:
    1. attack-stix-data GitHub releases API (gets latest release asset URL, then downloads)
    2. MITRE ATT&CK TAXII 2.1 API (paginated, small responses)
    3. Hardcoded comprehensive technique list (always works)
    """
    log.info("[mitre_attack] Fetching...")

    # ── Strategy 1: GitHub Releases API to get the latest versioned JSON ──────
    # The releases API returns small JSON with download URLs for each asset
    try:
        r = get("https://api.github.com/repos/mitre-attack/attack-stix-data/releases/latest",
                timeout=15)
        if r:
            release = r.json()
            for asset in release.get("assets", []):
                name = asset.get("name","")
                if "enterprise-attack" in name and name.endswith(".json") and "v" in name:
                    dl_url = asset.get("browser_download_url","")
                    log.info(f"[mitre_attack] Downloading release asset: {name}")
                    r2 = get(dl_url, timeout=120)
                    if r2 and len(r2.content) > 50_000:
                        bundle = r2.json()
                        result = _parse_mitre_bundle(bundle)
                        if result:
                            set_cache("mitre_attack", result, note=f"Release {release.get('tag_name','')}")
                            return
    except Exception as e:
        log.warning(f"[mitre_attack] Release API failed: {e}")

    # ── Strategy 2: Direct raw URLs with generous timeout ─────────────────────
    urls = [
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    ]
    for url in urls:
        try:
            r = get(url, timeout=120)
            if r and len(r.content) > 50_000:
                result = _parse_mitre_bundle(r.json())
                if result:
                    set_cache("mitre_attack", result, note="GitHub raw")
                    return
        except Exception as e:
            log.warning(f"[mitre_attack] {url[:50]} failed: {e}")
            continue

    # ── Strategy 3: Hardcoded comprehensive list (always works) ───────────────
    log.warning("[mitre_attack] All downloads failed — using built-in technique list")
    set_cache("mitre_attack", _builtin_mitre_techniques(),
              note="Built-in list (network issue prevented live download)")


def _parse_mitre_bundle(bundle):
    """Parse a MITRE ATT&CK STIX bundle into our technique format."""
    try:
        techniques = []
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern": continue
            if obj.get("x_mitre_deprecated") or obj.get("revoked"): continue
            att_id = url_ref = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    att_id  = ref.get("external_id", "")
                    url_ref = ref.get("url", "")
                    break
            if not att_id.startswith("T"): continue
            techniques.append({
                "id":             att_id,
                "name":           obj.get("name", ""),
                "tactics":        [k.get("phase_name","").replace("-"," ").title()
                                   for k in obj.get("kill_chain_phases", [])],
                "platforms":      obj.get("x_mitre_platforms", []),
                "description":    obj.get("description", "")[:300],
                "url":            url_ref,
                "is_subtechnique": "." in att_id,
                "source":         "MITRE ATT&CK",
            })
        techniques.sort(key=lambda x: x["id"])
        log.info(f"[mitre_attack] Parsed {len(techniques)} techniques from bundle")
        return techniques if techniques else None
    except Exception as e:
        log.error(f"[mitre_attack] Bundle parse error: {e}")
        return None


def _builtin_mitre_techniques():
    """
    Comprehensive built-in MITRE ATT&CK technique list.
    Used as fallback when all network sources fail.
    Covers all 14 tactics with the most common techniques.
    """
    techniques = [
        # Initial Access
        {"id":"T1566","name":"Phishing","tactics":["Initial Access"],"platforms":["Windows","macOS","Linux"],"description":"Adversaries may send phishing messages to gain access to victim systems.","url":"https://attack.mitre.org/techniques/T1566","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1566.001","name":"Phishing: Spearphishing Attachment","tactics":["Initial Access"],"platforms":["Windows","macOS","Linux"],"description":"Adversaries may send spearphishing emails with malicious attachments.","url":"https://attack.mitre.org/techniques/T1566/001","is_subtechnique":True,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1566.002","name":"Phishing: Spearphishing Link","tactics":["Initial Access"],"platforms":["Windows","macOS","Linux"],"description":"Adversaries may send spearphishing emails with malicious links.","url":"https://attack.mitre.org/techniques/T1566/002","is_subtechnique":True,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1190","name":"Exploit Public-Facing Application","tactics":["Initial Access"],"platforms":["Windows","Linux","macOS","Network"],"description":"Adversaries may attempt to exploit a weakness in an Internet-facing host.","url":"https://attack.mitre.org/techniques/T1190","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1133","name":"External Remote Services","tactics":["Initial Access","Persistence"],"platforms":["Windows","Linux","Containers","macOS"],"description":"Adversaries may leverage external-facing remote services to initially access a network.","url":"https://attack.mitre.org/techniques/T1133","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1078","name":"Valid Accounts","tactics":["Defense Evasion","Persistence","Privilege Escalation","Initial Access"],"platforms":["Windows","Azure AD","Office 365","SaaS","IaaS","Linux","macOS","Google Workspace","Containers","Network"],"description":"Adversaries may obtain and abuse credentials of existing accounts.","url":"https://attack.mitre.org/techniques/T1078","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1195","name":"Supply Chain Compromise","tactics":["Initial Access"],"platforms":["Linux","macOS","Windows"],"description":"Adversaries may manipulate products or delivery mechanisms prior to receipt.","url":"https://attack.mitre.org/techniques/T1195","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1091","name":"Replication Through Removable Media","tactics":["Initial Access","Lateral Movement"],"platforms":["Windows"],"description":"Adversaries may move onto systems via removable media.","url":"https://attack.mitre.org/techniques/T1091","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        # Execution
        {"id":"T1059","name":"Command and Scripting Interpreter","tactics":["Execution"],"platforms":["Windows","macOS","Linux","Network"],"description":"Adversaries may abuse command and script interpreters to execute commands.","url":"https://attack.mitre.org/techniques/T1059","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1059.001","name":"Command and Scripting Interpreter: PowerShell","tactics":["Execution"],"platforms":["Windows"],"description":"Adversaries may abuse PowerShell commands and scripts for execution.","url":"https://attack.mitre.org/techniques/T1059/001","is_subtechnique":True,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1059.003","name":"Command and Scripting Interpreter: Windows Command Shell","tactics":["Execution"],"platforms":["Windows"],"description":"Adversaries may abuse the Windows command shell for execution.","url":"https://attack.mitre.org/techniques/T1059/003","is_subtechnique":True,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1059.007","name":"Command and Scripting Interpreter: JavaScript","tactics":["Execution"],"platforms":["Windows","macOS","Linux"],"description":"Adversaries may abuse JavaScript for execution.","url":"https://attack.mitre.org/techniques/T1059/007","is_subtechnique":True,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1204","name":"User Execution","tactics":["Execution"],"platforms":["Linux","Windows","macOS"],"description":"An adversary may rely upon specific actions by a user to gain execution.","url":"https://attack.mitre.org/techniques/T1204","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1053","name":"Scheduled Task/Job","tactics":["Execution","Persistence","Privilege Escalation"],"platforms":["Windows","Linux","macOS","Containers"],"description":"Adversaries may abuse task scheduling functionality to facilitate execution.","url":"https://attack.mitre.org/techniques/T1053","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1047","name":"Windows Management Instrumentation","tactics":["Execution"],"platforms":["Windows"],"description":"Adversaries may abuse Windows Management Instrumentation (WMI) for execution.","url":"https://attack.mitre.org/techniques/T1047","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        # Persistence
        {"id":"T1547","name":"Boot or Logon Autostart Execution","tactics":["Persistence","Privilege Escalation"],"platforms":["Linux","macOS","Windows"],"description":"Adversaries may configure system settings to automatically execute a program.","url":"https://attack.mitre.org/techniques/T1547","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1543","name":"Create or Modify System Process","tactics":["Persistence","Privilege Escalation"],"platforms":["Windows","macOS","Linux"],"description":"Adversaries may create or modify system-level processes to repeatedly execute malicious payloads.","url":"https://attack.mitre.org/techniques/T1543","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1136","name":"Create Account","tactics":["Persistence"],"platforms":["Windows","macOS","Linux","Azure AD","Office 365","Google Workspace"],"description":"Adversaries may create an account to maintain access to victim systems.","url":"https://attack.mitre.org/techniques/T1136","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        # Privilege Escalation
        {"id":"T1068","name":"Exploitation for Privilege Escalation","tactics":["Privilege Escalation"],"platforms":["Linux","macOS","Windows","Containers"],"description":"Adversaries may exploit software vulnerabilities to elevate privileges.","url":"https://attack.mitre.org/techniques/T1068","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1055","name":"Process Injection","tactics":["Defense Evasion","Privilege Escalation"],"platforms":["Linux","macOS","Windows"],"description":"Adversaries may inject code into processes to evade process-based defenses.","url":"https://attack.mitre.org/techniques/T1055","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        # Defense Evasion
        {"id":"T1027","name":"Obfuscated Files or Information","tactics":["Defense Evasion"],"platforms":["Linux","macOS","Windows"],"description":"Adversaries may attempt to make an executable or file difficult to discover or analyze.","url":"https://attack.mitre.org/techniques/T1027","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1562","name":"Impair Defenses","tactics":["Defense Evasion"],"platforms":["Windows","macOS","Linux","Containers","IaaS","Network"],"description":"Adversaries may maliciously modify components of a victim environment.","url":"https://attack.mitre.org/techniques/T1562","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1070","name":"Indicator Removal","tactics":["Defense Evasion"],"platforms":["Linux","macOS","Windows","Containers","Network"],"description":"Adversaries may delete or modify artifacts generated within systems to remove evidence.","url":"https://attack.mitre.org/techniques/T1070","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1036","name":"Masquerading","tactics":["Defense Evasion"],"platforms":["Linux","macOS","Windows","Containers"],"description":"Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate.","url":"https://attack.mitre.org/techniques/T1036","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        # Credential Access
        {"id":"T1110","name":"Brute Force","tactics":["Credential Access"],"platforms":["Windows","Azure AD","Office 365","SaaS","IaaS","Linux","macOS","Google Workspace","Containers","Network"],"description":"Adversaries may use brute force techniques to gain access to accounts.","url":"https://attack.mitre.org/techniques/T1110","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1003","name":"OS Credential Dumping","tactics":["Credential Access"],"platforms":["Windows","Linux","macOS"],"description":"Adversaries may attempt to dump credentials to obtain account login information.","url":"https://attack.mitre.org/techniques/T1003","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1539","name":"Steal Web Session Cookie","tactics":["Credential Access"],"platforms":["Linux","macOS","Windows"],"description":"An adversary may steal web application or service session cookies.","url":"https://attack.mitre.org/techniques/T1539","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1621","name":"Multi-Factor Authentication Request Generation","tactics":["Credential Access"],"platforms":["Windows","Azure AD","Office 365","SaaS","IaaS","Linux","macOS","Google Workspace"],"description":"Adversaries may attempt to bypass MFA by generating repeated MFA requests.","url":"https://attack.mitre.org/techniques/T1621","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1557","name":"Adversary-in-the-Middle","tactics":["Credential Access","Collection"],"platforms":["Windows","macOS","Linux","Network"],"description":"Adversaries may intercept network traffic to capture or alter credentials.","url":"https://attack.mitre.org/techniques/T1557","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        # Discovery
        {"id":"T1082","name":"System Information Discovery","tactics":["Discovery"],"platforms":["Windows","IaaS","Linux","macOS","Network"],"description":"An adversary may attempt to get detailed information about the OS and hardware.","url":"https://attack.mitre.org/techniques/T1082","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1083","name":"File and Directory Discovery","tactics":["Discovery"],"platforms":["Linux","macOS","Windows"],"description":"Adversaries may enumerate files and directories to find specific information.","url":"https://attack.mitre.org/techniques/T1083","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1046","name":"Network Service Discovery","tactics":["Discovery"],"platforms":["Windows","IaaS","Linux","macOS","Containers","Network"],"description":"Adversaries may attempt to get a listing of services running on remote hosts.","url":"https://attack.mitre.org/techniques/T1046","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1018","name":"Remote System Discovery","tactics":["Discovery"],"platforms":["Linux","macOS","Windows","Network"],"description":"Adversaries may attempt to get a listing of other systems by IP address, hostname, etc.","url":"https://attack.mitre.org/techniques/T1018","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        # Lateral Movement
        {"id":"T1021","name":"Remote Services","tactics":["Lateral Movement"],"platforms":["Linux","macOS","Windows"],"description":"Adversaries may use valid accounts to log into a service specifically designed to accept remote connections.","url":"https://attack.mitre.org/techniques/T1021","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1021.001","name":"Remote Services: Remote Desktop Protocol","tactics":["Lateral Movement"],"platforms":["Windows"],"description":"Adversaries may use RDP to log into a system.","url":"https://attack.mitre.org/techniques/T1021/001","is_subtechnique":True,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1570","name":"Lateral Tool Transfer","tactics":["Lateral Movement"],"platforms":["Linux","macOS","Windows"],"description":"Adversaries may transfer tools or files between systems in a compromised environment.","url":"https://attack.mitre.org/techniques/T1570","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        # Collection
        {"id":"T1005","name":"Data from Local System","tactics":["Collection"],"platforms":["Linux","macOS","Windows"],"description":"Adversaries may search local system sources to find files of interest.","url":"https://attack.mitre.org/techniques/T1005","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1074","name":"Data Staged","tactics":["Collection"],"platforms":["Windows","macOS","Linux"],"description":"Adversaries may stage collected data in a central location or directory.","url":"https://attack.mitre.org/techniques/T1074","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1056","name":"Input Capture","tactics":["Collection","Credential Access"],"platforms":["Linux","macOS","Windows","Network"],"description":"Adversaries may use methods of capturing user input to obtain credentials.","url":"https://attack.mitre.org/techniques/T1056","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        # Command and Control
        {"id":"T1071","name":"Application Layer Protocol","tactics":["Command And Control"],"platforms":["Linux","macOS","Windows","Network"],"description":"Adversaries may communicate using application layer protocols to avoid detection.","url":"https://attack.mitre.org/techniques/T1071","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1071.001","name":"Application Layer Protocol: Web Protocols","tactics":["Command And Control"],"platforms":["Linux","macOS","Windows"],"description":"Adversaries may communicate using HTTP/HTTPS to avoid detection.","url":"https://attack.mitre.org/techniques/T1071/001","is_subtechnique":True,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1090","name":"Proxy","tactics":["Command And Control"],"platforms":["Linux","macOS","Windows","Network"],"description":"Adversaries may use a connection proxy to direct network traffic between systems.","url":"https://attack.mitre.org/techniques/T1090","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1105","name":"Ingress Tool Transfer","tactics":["Command And Control"],"platforms":["Linux","macOS","Windows"],"description":"Adversaries may transfer tools from an external system into a compromised environment.","url":"https://attack.mitre.org/techniques/T1105","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1573","name":"Encrypted Channel","tactics":["Command And Control"],"platforms":["Linux","macOS","Windows","Network"],"description":"Adversaries may employ a known encryption algorithm to conceal command and control traffic.","url":"https://attack.mitre.org/techniques/T1573","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        # Exfiltration
        {"id":"T1041","name":"Exfiltration Over C2 Channel","tactics":["Exfiltration"],"platforms":["Linux","macOS","Windows"],"description":"Adversaries may steal data by exfiltrating it over an existing C2 channel.","url":"https://attack.mitre.org/techniques/T1041","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1048","name":"Exfiltration Over Alternative Protocol","tactics":["Exfiltration"],"platforms":["Linux","macOS","Windows","Network"],"description":"Adversaries may steal data by exfiltrating it over a different protocol.","url":"https://attack.mitre.org/techniques/T1048","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1567","name":"Exfiltration Over Web Service","tactics":["Exfiltration"],"platforms":["Linux","macOS","Windows"],"description":"Adversaries may use an existing legitimate external web service to exfiltrate data.","url":"https://attack.mitre.org/techniques/T1567","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        # Impact
        {"id":"T1486","name":"Data Encrypted for Impact","tactics":["Impact"],"platforms":["Linux","macOS","Windows","IaaS"],"description":"Adversaries may encrypt data on target systems to interrupt availability (ransomware).","url":"https://attack.mitre.org/techniques/T1486","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1490","name":"Inhibit System Recovery","tactics":["Impact"],"platforms":["Windows","macOS","Linux","Network","Containers","IaaS"],"description":"Adversaries may delete or remove built-in data and turn off services to prevent recovery.","url":"https://attack.mitre.org/techniques/T1490","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1485","name":"Data Destruction","tactics":["Impact"],"platforms":["Windows","macOS","Linux","IaaS","Containers"],"description":"Adversaries may destroy data and files on specific systems or in large numbers.","url":"https://attack.mitre.org/techniques/T1485","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1498","name":"Network Denial of Service","tactics":["Impact"],"platforms":["Windows","Azure AD","Office 365","SaaS","IaaS","Linux","macOS","Google Workspace","Containers","Network"],"description":"Adversaries may perform Network Denial of Service (DoS) to degrade or block availability.","url":"https://attack.mitre.org/techniques/T1498","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1561","name":"Disk Wipe","tactics":["Impact"],"platforms":["Linux","macOS","Windows","Network"],"description":"Adversaries may wipe or corrupt raw disk data on specific systems.","url":"https://attack.mitre.org/techniques/T1561","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1499","name":"Endpoint Denial of Service","tactics":["Impact"],"platforms":["Windows","Azure AD","Office 365","SaaS","IaaS","Linux","macOS","Google Workspace","Containers","Network"],"description":"Adversaries may perform Endpoint Denial of Service (DoS) to degrade or block availability.","url":"https://attack.mitre.org/techniques/T1499","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        # Reconnaissance
        {"id":"T1595","name":"Active Scanning","tactics":["Reconnaissance"],"platforms":["PRE"],"description":"Adversaries may execute active reconnaissance scans to gather information.","url":"https://attack.mitre.org/techniques/T1595","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1592","name":"Gather Victim Host Information","tactics":["Reconnaissance"],"platforms":["PRE"],"description":"Adversaries may gather information about the victim's hosts.","url":"https://attack.mitre.org/techniques/T1592","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1589","name":"Gather Victim Identity Information","tactics":["Reconnaissance"],"platforms":["PRE"],"description":"Adversaries may gather information about the victim's identity that can be used for targeting.","url":"https://attack.mitre.org/techniques/T1589","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        # Resource Development
        {"id":"T1583","name":"Acquire Infrastructure","tactics":["Resource Development"],"platforms":["PRE"],"description":"Adversaries may buy, lease, or rent infrastructure that can be used during targeting.","url":"https://attack.mitre.org/techniques/T1583","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1584","name":"Compromise Infrastructure","tactics":["Resource Development"],"platforms":["PRE"],"description":"Adversaries may compromise third-party infrastructure that can be used during targeting.","url":"https://attack.mitre.org/techniques/T1584","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
        {"id":"T1588","name":"Obtain Capabilities","tactics":["Resource Development"],"platforms":["PRE"],"description":"Adversaries may buy and/or steal capabilities that can be used during targeting.","url":"https://attack.mitre.org/techniques/T1588","is_subtechnique":False,"source":"MITRE ATT&CK (built-in)"},
    ]
    techniques.sort(key=lambda x: x["id"])
    return techniques


PHISHING_CACHE_FILE = DATA_DIR / "phishing_cache.json"

def fetch_openphish():
    """
    OpenPhish Community Feed — no API key required.
    Tries 4 sources in order. Falls back to disk cache.
    Uses requests.get() directly (not get() helper) so 403s don't silently fail.
    """
    log.info("[openphish] Fetching...")

    SOURCES = [
        ("GitHub (refs)",  "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"),
        ("GitHub (main)",  "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt"),
        ("OpenPhish www",  "https://www.openphish.com/feed.txt"),
        ("OpenPhish",      "https://openphish.com/feed.txt"),
    ]

    text = None
    for label, url in SOURCES:
        try:
            r = requests.get(url, timeout=20, headers={
                "User-Agent": "curl/7.88.1",  # plain curl UA avoids blocks
                "Accept":     "text/plain, */*",
            })
            log.info(f"[openphish] {label} → HTTP {r.status_code}")
            if r.status_code == 200 and r.text.strip():
                text = r.text
                log.info(f"[openphish] Got {len(r.text.splitlines())} lines from {label}")
                break
        except Exception as e:
            log.warning(f"[openphish] {label} failed: {e}")

    if not text:
        # Fall back to disk cache
        if PHISHING_CACHE_FILE.exists():
            try:
                cached  = json.loads(PHISHING_CACHE_FILE.read_text())
                entries = cached.get("data", [])
                age_h   = (datetime.now(timezone.utc).timestamp() -
                           cached.get("saved_at", 0)) / 3600
                set_cache("openphish", entries, "ok",
                          note=f"All sources blocked — disk cache ({len(entries)} URLs, {age_h:.0f}h old)")
                log.info(f"[openphish] Using disk cache: {len(entries)} URLs, {age_h:.0f}h old")
                return
            except Exception as ce:
                log.warning(f"[openphish] Disk cache read failed: {ce}")
        set_cache("openphish", [], "error",
                  note="OpenPhish: all 4 sources failed, no disk cache")
        return

    try:
        out   = []
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        for line in text.splitlines():
            url_str = line.strip()
            if not url_str.startswith("http"):
                continue
            try:
                host = urlparse(url_str).netloc
            except Exception:
                host = ""
            out.append({
                "url":             url_str,
                "host":            host,
                "online":          "yes",
                "verified":        "yes",
                "submission_time": today,
                "target":          "",
                "source":          "OpenPhish",
            })

        # Persist to disk cache
        try:
            PHISHING_CACHE_FILE.write_text(json.dumps({
                "data":     out,
                "saved_at": datetime.now(timezone.utc).timestamp(),
            }))
        except Exception as ce:
            log.warning(f"[openphish] Disk cache write failed: {ce}")

        set_cache("openphish", out)
        log.info(f"[openphish] {len(out)} phishing URLs cached to disk + memory")

    except Exception as e:
        log.error(f"[openphish] Parse error: {e}")
        set_cache("openphish", [], "error")


def _preload_phishing_cache():
    """Load disk cache on startup so the page isn't blank while feed fetches."""
    if not PHISHING_CACHE_FILE.exists():
        return
    try:
        cached  = json.loads(PHISHING_CACHE_FILE.read_text())
        entries = cached.get("data", [])
        age_h   = (datetime.now(timezone.utc).timestamp() -
                   cached.get("saved_at", 0)) / 3600
        if entries:
            set_cache("openphish", entries, "ok",
                      note=f"Using disk cache ({len(entries)} URLs, {age_h:.0f}h old) — live fetch scheduled")
            log.info(f"[openphish] Pre-loaded {len(entries)} URLs from disk cache ({age_h:.0f}h old)")
    except Exception as e:
        log.warning(f"[openphish] Could not pre-load disk cache: {e}")


def fetch_blocklist_de():
    """
    blocklist.de — German Fail2Ban reporting service.
    Collects SSH/RDP/Apache/FTP/mail attackers from European server farms.
    Free, no key. Updated every 30 min. ~17,000 IPs globally.
    """
    log.info("[blocklist_de] Fetching...")
    # 'all' list covers SSH, mail, apache, ftp, sip, bots, etc.
    r = get("https://lists.blocklist.de/lists/all.txt", timeout=30)
    if not r:
        set_cache("blocklist_de", cache["blocklist_de"]["data"] or [], "error")
        return
    try:
        lines = [l.strip() for l in r.text.splitlines()
                 if l.strip() and not l.startswith("#")]
        out = []
        for ip in lines[:3000]:
            # Basic IPv4 validation
            parts = ip.split(".")
            if len(parts) == 4:
                out.append({
                    "ip":     ip,
                    "source": "blocklist.de",
                    "type":   "attacker",
                    "note":   "Fail2Ban reported attacker (SSH/Mail/Apache/FTP)",
                })
        set_cache("blocklist_de", out)
    except Exception as e:
        log.error(f"[blocklist_de] {e}")
        set_cache("blocklist_de", [], "error")


def fetch_dshield():
    """
    SANS Internet Storm Center / DShield Top Attackers.
    Global honeypot network run by SANS — updated every 5 minutes.
    JSON format includes country code — no geo lookup needed for these!
    Free, no key.
    """
    log.info("[dshield] Fetching...")
    r = get("https://isc.sans.edu/api/sources/attacks/30/10000?json", timeout=20)
    if not r:
        # Fallback to plain text blocklist
        r = get("https://feeds.dshield.org/top10-2.txt", timeout=20)
        if not r:
            set_cache("dshield", cache["dshield"]["data"] or [], "error")
            return
        try:
            lines = [l.strip() for l in r.text.splitlines()
                     if l.strip() and not l.startswith("#")]
            out = []
            for line in lines[:500]:
                parts = line.split()
                if parts:
                    out.append({"ip": parts[0], "country": "", "attacks": 0,
                                "source": "DShield", "type": "scanner"})
            set_cache("dshield", out)
        except Exception as e:
            log.error(f"[dshield] fallback parse: {e}")
            set_cache("dshield", [], "error")
        return
    try:
        data = r.json()
        # DShield JSON: list of {ip, count, attacks, Hostname, country, ...}
        entries = data if isinstance(data, list) else data.get("sources", [])
        out = []
        for e in entries[:2000]:
            ip      = e.get("ip") or e.get("ipval") or e.get("source","")
            country = (e.get("country") or "").strip().upper()
            attacks = e.get("attacks") or e.get("count") or 0
            if ip:
                out.append({
                    "ip":      str(ip),
                    "country": country[:2] if len(country) >= 2 else "",
                    "attacks": int(attacks),
                    "source":  "DShield/SANS",
                    "type":    "scanner",
                    "note":    f"SANS ISC honeypot — {attacks} attacks",
                })
        set_cache("dshield", out)
    except Exception as e:
        log.error(f"[dshield] JSON parse: {e}")
        set_cache("dshield", [], "error")


def fetch_ipsum():
    """
    IPsum — community-aggregated blocklist from 30+ sources.
    Plain text, one IP per line, updated daily.
    Covers IPs seen attacking honeypots internationally.
    Free, no key, hosted on GitHub.
    """
    log.info("[ipsum] Fetching...")
    # Level 3 = seen on 3+ different lists (good signal/noise ratio)
    r = get(
        "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        timeout=30
    )
    if not r:
        set_cache("ipsum", cache["ipsum"]["data"] or [], "error")
        return
    try:
        lines = [l.strip() for l in r.text.splitlines()
                 if l.strip() and not l.startswith("#")]
        out = []
        for line in lines[:3000]:
            # Format: IP\tHIT_COUNT
            parts = line.split("\t")
            ip    = parts[0].strip()
            hits  = int(parts[1].strip()) if len(parts) > 1 else 1
            if ip and "." in ip:
                out.append({
                    "ip":     ip,
                    "hits":   hits,
                    "source": "IPsum",
                    "type":   "blocklist",
                    "note":   f"Seen on {hits} threat lists",
                })
        set_cache("ipsum", out)
    except Exception as e:
        log.error(f"[ipsum] {e}")
        set_cache("ipsum", [], "error")


def fetch_cinsscore():
    """
    CINS Score (Collective Intelligence Network Security) Army list.
    IPs with bad reputation from CINS sensors — global coverage.
    Free, no key, plain text.
    """
    log.info("[cinsscore] Fetching...")
    r = get("https://cinsscore.com/list/ci-badguys.txt", timeout=20)
    if not r:
        set_cache("cinsscore", cache["cinsscore"]["data"] or [], "error")
        return
    try:
        lines = [l.strip() for l in r.text.splitlines()
                 if l.strip() and not l.startswith("#") and "." in l]
        out = [{"ip": ip, "source": "CINS Score", "type": "bad_reputation",
                "note": "CINS Army bad reputation"}
               for ip in lines[:3000]]
        set_cache("cinsscore", out)
    except Exception as e:
        log.error(f"[cinsscore] {e}")
        set_cache("cinsscore", [], "error")


ABUSEIPDB_INDEX_FILE = DATA_DIR / "abuseipdb_index.json"

def _save_abuseipdb_index(data):
    """Persist a successful AbuseIPDB fetch to disk so it survives restarts."""
    try:
        ABUSEIPDB_INDEX_FILE.write_text(json.dumps({
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "count":      len(data),
            "data":       data,
        }, indent=2))
        log.info(f"[abuseipdb] Index saved to disk ({len(data)} IPs)")
    except Exception as e:
        log.warning(f"[abuseipdb] Could not save index: {e}")

def _load_abuseipdb_index():
    """
    Load the last successfully saved AbuseIPDB list from disk.
    Returns (data, fetched_at_str) or (None, None) if no file exists.
    """
    try:
        if not ABUSEIPDB_INDEX_FILE.exists():
            return None, None
        obj = json.loads(ABUSEIPDB_INDEX_FILE.read_text())
        data       = obj.get("data", [])
        fetched_at = obj.get("fetched_at", "")
        return data, fetched_at
    except Exception as e:
        log.warning(f"[abuseipdb] Could not load index: {e}")
        return None, None

def _abuseipdb_index_age_str(fetched_at_str):
    """Return a human-readable age string like '3 hours' or '1 day 4 hours'."""
    try:
        fetched_at = datetime.fromisoformat(fetched_at_str.replace("Z", "+00:00"))
        delta      = datetime.now(timezone.utc) - fetched_at
        total_h    = int(delta.total_seconds() // 3600)
        days, hrs  = divmod(total_h, 24)
        if days > 0:
            return f"{days}d {hrs}h"
        return f"{total_h}h"
    except Exception:
        return "unknown"

def _use_abuseipdb_index(reason):
    """
    Fall back to the on-disk index. Sets cache with an informative note
    showing how old the indexed list is.
    """
    data, fetched_at = _load_abuseipdb_index()
    if data:
        age  = _abuseipdb_index_age_str(fetched_at)
        note = (f"Rate-limited — using indexed list ({len(data)} IPs, "
                f"{age} old). Live data resumes next cycle.")
        set_cache("abuseipdb", data, "indexed", note=note)
        log.info(f"[abuseipdb] Using disk index ({len(data)} IPs, {age} old) — {reason}")
    else:
        set_cache("abuseipdb", [], "error",
                  note=f"AbuseIPDB: {reason}. No index file found yet.")
        log.warning(f"[abuseipdb] {reason} and no index available")

def fetch_abuseipdb():
    """
    AbuseIPDB blacklist — crowdsourced global attacker IPs.
    Free tier: up to 10,000 IPs at confidenceMinimum=90.
    Requires free API key from abuseipdb.com.

    On first startup or after a rate limit, falls back to the last
    successfully fetched list stored in data/abuseipdb_index.json.
    """
    log.info("[abuseipdb] Fetching...")
    key = _clean_key(CONFIG.get("ABUSEIPDB_API_KEY", ""))
    if not key:
        # No key — load index if available, otherwise needs_key
        data, fetched_at = _load_abuseipdb_index()
        if data:
            age  = _abuseipdb_index_age_str(fetched_at)
            note = (f"No API key set — using indexed list ({len(data)} IPs, "
                    f"{age} old). Add ABUSEIPDB_API_KEY to config.json.")
            set_cache("abuseipdb", data, "indexed", note=note)
        else:
            set_cache("abuseipdb", [], "needs_key",
                      note="Add free ABUSEIPDB_API_KEY to config.json — abuseipdb.com")
        return

    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": key, "Accept": "application/json",
                     "User-Agent": "TOOB-OSINT/2.3"},
            params={"confidenceMinimum": 90, "limit": 10000},
            timeout=30,
        )

        if r.status_code == 401:
            set_cache("abuseipdb", [], "error",
                      note="AbuseIPDB: Invalid API key (401) — check config.json")
            log.error("[abuseipdb] 401 Unauthorized — check your API key")
            return

        if r.status_code == 429:
            _use_abuseipdb_index("Rate limited (429)")
            return

        if r.status_code == 422:
            # Limit too high for plan — retry with lower limit
            log.warning("[abuseipdb] 422 — retrying with limit=1000")
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/blacklist",
                headers={"Key": key, "Accept": "application/json",
                         "User-Agent": "TOOB-OSINT/2.3"},
                params={"confidenceMinimum": 90, "limit": 1000},
                timeout=30,
            )

        if not r.ok:
            _use_abuseipdb_index(f"HTTP {r.status_code}")
            return

        body    = r.json()
        entries = body.get("data", [])
        out = []
        for e in entries:
            country = (e.get("countryCode") or "").strip().upper()
            out.append({
                "ip":         e.get("ipAddress", ""),
                "country":    country,
                "confidence": e.get("abuseConfidenceScore", 100),
                "last_seen":  (e.get("lastReportedAt") or "")[:10],
                "source":     "AbuseIPDB",
                "type":       "abusive",
                "note":       f"Confidence {e.get('abuseConfidenceScore', 100)}%",
            })

        # Success — save to disk index for future restarts/rate limits
        _save_abuseipdb_index(out)
        set_cache("abuseipdb", out, note=f"{len(out)} IPs (live)")
        log.info(f"[abuseipdb] {len(out)} IPs loaded and indexed")

    except Exception as e:
        log.error(f"[abuseipdb] {e}")
        _use_abuseipdb_index(f"Exception: {str(e)[:40]}")


def _preload_abuseipdb_index():
    """
    Called once at startup — if an index file exists on disk, load it
    immediately so the map has data before the first scheduled fetch.
    """
    data, fetched_at = _load_abuseipdb_index()
    if data:
        age  = _abuseipdb_index_age_str(fetched_at)
        note = (f"Using indexed list ({len(data)} IPs, {age} old). "
                f"Live fetch scheduled.")
        set_cache("abuseipdb", data, "indexed", note=note)
        log.info(f"[abuseipdb] Pre-loaded {len(data)} IPs from disk index ({age} old)")
    else:
        log.info("[abuseipdb] No index file found — will populate after first live fetch")




# ══════════════════════════════════════════════════════════════════════════════
# FLASK
# ══════════════════════════════════════════════════════════════════════════════

app  = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins":"*"}})

def ioc_type(t):
    return {"ip:port":"IP","domain":"Domain","url":"URL","md5_hash":"Hash-MD5",
            "sha256_hash":"Hash-SHA256","sha1_hash":"Hash-SHA1",
            "email":"Email"}.get((t or "").lower(), t or "Unknown")

def sev(c):
    return "Critical" if c>=90 else "High" if c>=70 else "Medium" if c>=50 else "Low"


# ══════════════════════════════════════════════════════════════════════════════
# AUTH SYSTEM
# Users: backend/data/users.json  (PBKDF2-SHA256, 260k iterations)
# Tokens: backend/data/tokens.json (bearer tokens, 12h expiry)
# Feed routes are NOT protected — auth only gates config/key changes
# ══════════════════════════════════════════════════════════════════════════════

AUTH_ITERATIONS = 260_000

def _hash_password(plaintext, salt=None):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", plaintext.encode(), salt, AUTH_ITERATIONS, 32)
    return salt.hex(), dk.hex()

def _verify_password(plaintext, salt_hex, stored_hash_hex):
    salt = bytes.fromhex(salt_hex)
    _, candidate = _hash_password(plaintext, salt)
    return hmac.compare_digest(candidate, stored_hash_hex)

def _load_users():
    if USERS_FILE.exists():
        try: return json.loads(USERS_FILE.read_text())
        except: pass
    return {}

def _save_users(users):
    USERS_FILE.write_text(json.dumps(users, indent=2))

def _no_users():
    return len(_load_users()) == 0

# In-memory token store
_tokens = {}

def _load_tokens():
    global _tokens
    if TOKEN_FILE.exists():
        try:
            raw = json.loads(TOKEN_FILE.read_text())
            now = datetime.now(timezone.utc).isoformat()
            _tokens = {k: v for k, v in raw.items() if v.get("expires","") > now}
        except: _tokens = {}

def _save_tokens():
    TOKEN_FILE.write_text(json.dumps(_tokens, indent=2))

def _new_token(username, role):
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat()
    _tokens[token] = {"username": username, "role": role, "expires": expires}
    _save_tokens()
    return token

def _validate_token(token):
    if not token or token not in _tokens:
        return None
    payload = _tokens[token]
    if payload.get("expires","") < datetime.now(timezone.utc).isoformat():
        del _tokens[token]; _save_tokens()
        return None
    return payload

def _get_token():
    auth = request.headers.get("Authorization","")
    if auth.startswith("Bearer "): return auth[7:]
    return request.headers.get("X-Auth-Token","")

_load_tokens()

@app.route("/api/auth/status")
def api_auth_status():
    no_users = _no_users()
    payload  = _validate_token(_get_token())
    return jsonify({
        "auth_required": not no_users,
        "authenticated": bool(payload) or no_users,
        "username":      payload["username"] if payload else "",
        "role":          payload["role"]     if payload else "",
        "no_users":      no_users,
    })

@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    data     = request.get_json() or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    users = _load_users()
    user  = users.get(username)
    if not user or not _verify_password(password, user["salt"], user["hash"]):
        log.warning(f"[auth] Failed login: {username}")
        return jsonify({"error": "Invalid username or password"}), 401
    token = _new_token(username, user.get("role","analyst"))
    log.info(f"[auth] Login: {username}")
    return jsonify({"token": token, "username": username, "role": user.get("role","analyst")})

@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    token = _get_token()
    if token in _tokens:
        del _tokens[token]; _save_tokens()
    return jsonify({"message": "Logged out"})

@app.route("/api/auth/status_check")
def api_auth_status_check():
    return api_auth_status()

@app.route("/api/auth/users", methods=["GET"])
def api_auth_list_users():
    payload = _validate_token(_get_token())
    if not _no_users() and (not payload or payload.get("role") != "admin"):
        return jsonify({"error": "Admin only"}), 403
    users = _load_users()
    return jsonify({"users": [{"username": u, "role": v.get("role","analyst")} for u,v in users.items()]})

@app.route("/api/auth/users", methods=["POST"])
def api_auth_create_user():
    no_users = _no_users()
    if not no_users:
        payload = _validate_token(_get_token())
        if not payload or payload.get("role") != "admin":
            return jsonify({"error": "Admin only"}), 403
    data     = request.get_json() or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    role     = data.get("role", "admin" if no_users else "analyst")
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if not re.match(r"^[a-z0-9_.+-]+$", username):
        return jsonify({"error": "Username: letters, numbers, _ . - only"}), 400
    users = _load_users()
    if username in users:
        return jsonify({"error": "Username already exists"}), 409
    salt_hex, hash_hex = _hash_password(password)
    users[username] = {"salt": salt_hex, "hash": hash_hex, "role": role,
                       "created": datetime.now(timezone.utc).isoformat()}
    _save_users(users)
    log.info(f"[auth] User created: {username} ({role})")
    token = _new_token(username, role) if no_users else None
    return jsonify({"message": f"User '{username}' created", "role": role,
                    "token": token, "username": username}), 201

@app.route("/api/auth/users/<username>", methods=["DELETE"])
def api_auth_delete_user(username):
    payload = _validate_token(_get_token())
    if not payload or payload.get("role") != "admin":
        return jsonify({"error": "Admin only"}), 403
    username = username.strip().lower()
    if username == payload["username"]:
        return jsonify({"error": "Cannot delete your own account"}), 400
    users = _load_users()
    if username not in users:
        return jsonify({"error": "User not found"}), 404
    del users[username]; _save_users(users)
    log.info(f"[auth] User deleted: {username}")
    return jsonify({"message": f"User '{username}' deleted"})

@app.route("/api/auth/reset-users", methods=["POST"])
def api_auth_reset_users():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify({"error": "Localhost only"}), 403
    data = request.get_json() or {}
    if data.get("reset_key") != "TOOB_RESET":
        return jsonify({"error": "Invalid reset key"}), 403
    if USERS_FILE.exists(): USERS_FILE.unlink()
    if TOKEN_FILE.exists(): TOKEN_FILE.unlink()
    global _tokens; _tokens = {}
    log.warning("[auth] Users and tokens RESET")
    return jsonify({"message": "All users cleared. Create a new admin account."})


LAYOUTS_DIR = DATA_DIR / "layouts"
LAYOUTS_DIR.mkdir(exist_ok=True)

def _layout_file(username: str) -> Path:
    # Sanitise username to a safe filename
    safe = "".join(c for c in username if c.isalnum() or c in "-_").lower() or "_default"
    return LAYOUTS_DIR / f"{safe}.json"

@app.route("/api/layout", methods=["GET"])
def api_layout_get():
    payload = _validate_token(_get_token())
    username = payload["username"] if payload else "_default"
    f = _layout_file(username)
    if f.exists():
        try:
            return jsonify({"layout": json.loads(f.read_text()), "username": username})
        except Exception:
            pass
    return jsonify({"layout": None, "username": username})

@app.route("/api/layout", methods=["POST"])
def api_layout_save():
    payload = _validate_token(_get_token())
    # Allow save when auth is disabled (no_users) or when authenticated
    if not _no_users() and not payload:
        return jsonify({"error": "Unauthorized"}), 401
    username = payload["username"] if payload else "_default"
    data = request.get_json() or {}
    layout = data.get("layout")
    if not isinstance(layout, list):
        return jsonify({"error": "layout must be an array"}), 400
    f = _layout_file(username)
    f.write_text(json.dumps(layout))
    return jsonify({"saved": True, "username": username})


@app.route("/api/status")
def api_status():
    with lock:
        feeds = {k: {"status":v["status"],"updated":v["updated"],
                     "count":v["count"],"note":v.get("note","")}
                 for k,v in cache.items()}
    return jsonify({"server_time":datetime.now(timezone.utc).isoformat(), "feeds":feeds})


@app.route("/api/keys_status")
def api_keys_status():
    """Which keys are configured."""
    return jsonify({
        "malwarebazaar": bool(CONFIG.get("MALWAREBAZAAR_API_KEY","")),
        "threatfox":     bool(CONFIG.get("THREATFOX_API_KEY","")),
        "urlhaus":       bool(CONFIG.get("URLHAUS_API_KEY","")),
        "nvd":           bool(CONFIG.get("NVD_API_KEY","")),
        "abuseipdb":     bool(CONFIG.get("ABUSEIPDB_API_KEY","")),
        "road511":       bool(CONFIG.get("ROAD511_API_KEY","")),
    })


@app.route("/api/config", methods=["POST"])
def api_config_set():
    """Save API keys sent from the Settings page."""
    try:
        data = request.get_json() or {}
        key_map = {
            "malwarebazaar": "MALWAREBAZAAR_API_KEY",
            "threatfox":     "THREATFOX_API_KEY",
            "urlhaus":       "URLHAUS_API_KEY",
            "nvd":           "NVD_API_KEY",
            "abuseipdb":     "ABUSEIPDB_API_KEY",
            "road511":       "ROAD511_API_KEY",
        }
        changed = []
        for short, full in key_map.items():
            if short in data and data[short] is not None:
                CONFIG[full] = data[short].strip()
                changed.append(short)
        save_config()
        # Re-trigger affected feeds immediately
        trigger_map = {
            "malwarebazaar": fetch_malware_bazaar,
            "threatfox":     fetch_threatfox,
            "urlhaus":       fetch_urlhaus,
            "nvd":           fetch_nvd_cves,
            "abuseipdb":     fetch_abuseipdb,
            "road511":       fetch_all_cameras,
        }
        for k in changed:
            if k in trigger_map:
                threading.Thread(target=trigger_map[k], daemon=True).start()
        return jsonify({"message": f"Saved and re-fetching: {', '.join(changed)}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/feed/<feed_name>")
def api_feed(feed_name):
    if feed_name == "phishtank": feed_name = "openphish"
    if feed_name not in cache:
        return jsonify({"error":"Unknown feed"}), 404
    d     = get_cache(feed_name)
    limit = request.args.get("limit", 200, type=int)
    items = d["data"][:limit] if isinstance(d["data"], list) else d["data"]
    return jsonify({"feed":feed_name,"count":len(items),"updated":d["updated"],
                    "status":d["status"],"note":d.get("note",""),"data":items})


@app.route("/api/iocs")
def api_iocs():
    iocs  = []
    limit = request.args.get("limit", 500, type=int)
    for i in get_cache("threatfox")["data"]:
        iocs.append({"type":ioc_type(i.get("ioc_type","")),"value":i.get("ioc",""),
                     "severity":sev(i.get("confidence",75)),"actor":i.get("malware","Unknown"),
                     "firstSeen":str(i.get("first_seen",""))[:10],
                     "lastSeen":str(i.get("last_seen","") or i.get("first_seen",""))[:10],
                     "confidence":i.get("confidence",75),"notes":i.get("ioc_type_desc",""),
                     "tags":i.get("tags") or [],"source":"ThreatFox",
                     "threat_type":i.get("threat_type","")})
    for f in get_cache("feodo")["data"]:
        iocs.append({"type":"IP","value":f"{f.get('ip','')}:{f.get('port','')}",
                     "severity":"High","actor":f.get("malware","Unknown"),
                     "firstSeen":str(f.get("first_seen",""))[:10],
                     "lastSeen":str(f.get("last_online","") or f.get("first_seen",""))[:10],
                     "confidence":90,"notes":f"C2 — {f.get('malware','')} / {f.get('country','')}",
                     "tags":["C2","Botnet",f.get("malware","")],"source":"Feodo Tracker",
                     "threat_type":"botnet_cc"})
    for u in get_cache("urlhaus")["data"]:
        iocs.append({"type":"URL","value":u.get("url",""),
                     "severity":"High" if u.get("url_status")=="online" else "Medium",
                     "actor":"Unknown","firstSeen":str(u.get("date_added",""))[:10],
                     "lastSeen":str(u.get("date_added",""))[:10],"confidence":85,
                     "notes":u.get("threat",""),"tags":u.get("tags") or [],
                     "source":"URLhaus","threat_type":u.get("threat","")})
    iocs.sort(key=lambda x: x.get("firstSeen",""), reverse=True)
    return jsonify({"count":len(iocs),"data":iocs[:limit]})


@app.route("/api/malware")
def api_malware():
    d = get_cache("malware_bazaar")
    return jsonify({"count":d["count"],"updated":d["updated"],"status":d["status"],
                    "note":d.get("note",""),"data":d["data"]})


@app.route("/api/vulns")
def api_vulns():
    kev     = get_cache("cisa_kev")["data"]
    nvd     = get_cache("nvd_cves")["data"]
    kev_ids = {v["cve_id"] for v in kev}
    vulns   = []
    for v in nvd:
        vulns.append({"cve_id":v["cve_id"],"title":v["cve_id"],"description":v["description"],
                      "cvss":v["cvss_score"],"severity":(v["severity"] or "Unknown").capitalize(),
                      "published":v["published"],"exploited":v["cve_id"] in kev_ids,
                      "source":"NVD","references":v.get("references",[]),"weaknesses":v.get("weaknesses",[])})
    nvd_ids = {v["cve_id"] for v in nvd}
    for v in kev:
        if v["cve_id"] not in nvd_ids:
            vulns.append({"cve_id":v["cve_id"],"title":v["name"],"description":v["short_desc"],
                          "cvss":None,"severity":"High","published":v["date_added"],"exploited":True,
                          "ransomware":v["known_ransomware"],"action":v["action"],"due_date":v["due_date"],
                          "vendor":v["vendor"],"product":v["product"],"source":"CISA KEV"})
    vulns.sort(key=lambda x: (not x.get("exploited",False), -(x.get("cvss") or 0)))
    return jsonify({"count":len(vulns),"data":vulns[:300]})


@app.route("/api/phishing")
def api_phishing():
    d = get_cache("openphish")
    return jsonify({"count":d["count"],"updated":d["updated"],"note":d.get("note",""),
                    "data":d["data"][:200]})


@app.route("/api/mitre")
def api_mitre():
    data   = get_cache("mitre_attack")["data"]
    tactic = request.args.get("tactic","").lower()
    q      = request.args.get("q","").lower()
    if tactic: data = [t for t in data if any(tactic in ta.lower() for ta in t.get("tactics",[]))]
    if q:      data = [t for t in data if q in t["name"].lower() or q in t["id"].lower()]
    return jsonify({"count":len(data),"data":data[:600]})


@app.route("/api/stream")
def api_stream():
    events = []
    for i in get_cache("threatfox")["data"][:15]:
        events.append({"source":"ThreatFox","type":"ioc","severity":sev(i.get("confidence",75)),
                        "message":f"IOC: {i.get('ioc','')} — {i.get('malware','')}",
                        "time":str(i.get("first_seen","")),"tags":i.get("tags") or []})
    for s in get_cache("malware_bazaar")["data"][:10]:
        events.append({"source":"MalwareBazaar","type":"malware","severity":"High",
                        "message":f"Sample: {s.get('signature','?')} ({s.get('file_type','')})",
                        "time":str(s.get("first_seen","")),"tags":s.get("tags") or []})
    for u in get_cache("urlhaus")["data"][:8]:
        events.append({"source":"URLhaus","type":"url",
                        "severity":"High" if u.get("url_status")=="online" else "Medium",
                        "message":f"Malicious URL: {u.get('url','')[:55]}",
                        "time":str(u.get("date_added","")),"tags":u.get("tags") or []})
    for v in get_cache("cisa_kev")["data"][:5]:
        events.append({"source":"CISA KEV","type":"vuln","severity":"Critical",
                        "message":f"Exploited: {v.get('cve_id','')} — {v.get('name','')}",
                        "time":v.get("date_added",""),"tags":["CVE","Exploited"]})
    events.sort(key=lambda x: x.get("time",""), reverse=True)
    return jsonify({"count":len(events),"data":events[:60]})


@app.route("/api/pivot/<path:query>")
def api_pivot(query):
    """
    IOC Pivot Tool — searches ALL caches for a given indicator.
    Accepts: IP, domain, URL, MD5, SHA256, SHA1, CVE ID, malware family name.
    Returns matches across every feed + live enrichment data.
    """
    import re as _re
    q    = query.strip().lower()
    qraw = query.strip()
    out  = {
        "query":      qraw,
        "ioc_type":   _detect_ioc_type(qraw),
        "matches":    [],
        "feeds_hit":  [],
        "feeds_miss": [],
        "enrichment": {},
        "external_links": _build_external_links(qraw),
    }

    # ── Search every feed cache ───────────────────────────────────
    feed_searches = [
        ("ThreatFox",    "threatfox",    lambda e: q in (e.get("ioc","")).lower() or q in (e.get("malware","")).lower()),
        ("Feodo Tracker","feodo",        lambda e: q in (e.get("ip","")).lower() or q in (e.get("malware","")).lower()),
        ("URLhaus",      "urlhaus",      lambda e: q in (e.get("url","")).lower() or q in (e.get("host","")).lower()),
        ("MalwareBazaar","malware_bazaar",lambda e: q in (e.get("sha256_hash","")).lower() or q in (e.get("md5_hash","")).lower() or q in (e.get("sha1_hash","")).lower() or q in (e.get("signature","")).lower()),
        ("CISA KEV",     "cisa_kev",     lambda e: q in (e.get("cve_id","")).lower() or q in (e.get("name","")).lower() or q in (e.get("vendor_project","")).lower()),
        ("NVD/NIST",     "nvd_cves",     lambda e: q in (e.get("cve_id","")).lower() or q in (e.get("description","")).lower()),
        ("SSL Blacklist","ssl_blacklist", lambda e: q in (e.get("sha1","")).lower() or q in (e.get("name","")).lower()),
        ("AbuseIPDB",    "abuseipdb",    lambda e: q in (e.get("ip","")).lower()),
        ("DShield/SANS", "dshield",      lambda e: q in (e.get("ip","")).lower()),
        ("blocklist.de", "blocklist_de", lambda e: q in (e.get("ip","")).lower()),
        ("IPsum",        "ipsum",        lambda e: q in (e.get("ip","")).lower()),
        ("CINS Score",   "cinsscore",    lambda e: q in (e.get("ip","")).lower()),
        ("OpenPhish",    "openphish",    lambda e: q in (e.get("url","")).lower() or q in (e.get("host","")).lower()),
    ]

    for label, cache_key, matcher in feed_searches:
        try:
            hits = [e for e in get_cache(cache_key)["data"] if matcher(e)]
            if hits:
                out["feeds_hit"].append(label)
                for h in hits[:10]:  # cap per feed
                    out["matches"].append({"feed": label, "data": h})
            else:
                out["feeds_miss"].append(label)
        except Exception:
            out["feeds_miss"].append(label)

    # ── Live enrichment based on IOC type ────────────────────────
    ioc_type_val = out["ioc_type"]

    if ioc_type_val == "ip":
        # Geo + reverse DNS
        try:
            geo_r = requests.get(
                f"http://ip-api.com/json/{qraw}",
                params={"fields": "status,country,countryCode,regionName,city,isp,org,as,lat,lon,reverse"},
                timeout=8
            )
            if geo_r.ok:
                gd = geo_r.json()
                if gd.get("status") == "success":
                    out["enrichment"]["geo"] = {
                        "country":     gd.get("country",""),
                        "country_code":gd.get("countryCode",""),
                        "region":      gd.get("regionName",""),
                        "city":        gd.get("city",""),
                        "isp":         gd.get("isp",""),
                        "org":         gd.get("org",""),
                        "asn":         gd.get("as",""),
                        "lat":         gd.get("lat"),
                        "lon":         gd.get("lon"),
                        "rdns":        gd.get("reverse",""),
                    }
        except Exception as e:
            log.warning(f"[pivot] geo lookup failed: {e}")

    elif ioc_type_val in ("domain", "url"):
        # Extract hostname for domain lookups
        try:
            from urllib.parse import urlparse as _urlparse
            host = _urlparse(qraw).netloc or qraw
            out["enrichment"]["host"] = host
        except Exception:
            pass

    # ── Confidence score ─────────────────────────────────────────
    n_hits = len(out["feeds_hit"])
    source_weights = {
        "CISA KEV": 30, "ThreatFox": 20, "Feodo Tracker": 20,
        "MalwareBazaar": 15, "AbuseIPDB": 15, "URLhaus": 12,
        "SSL Blacklist": 10, "DShield/SANS": 10, "NVD/NIST": 10,
        "blocklist.de": 8, "IPsum": 7, "CINS Score": 6, "OpenPhish": 10,
    }
    raw_score = sum(source_weights.get(f, 5) for f in out["feeds_hit"])
    out["confidence_score"] = min(100, raw_score)
    out["confidence_label"] = (
        "Critical" if raw_score >= 40 else
        "High"     if raw_score >= 20 else
        "Medium"   if raw_score >= 10 else
        "Low"      if raw_score >  0  else
        "Unknown"
    )
    out["total_matches"] = len(out["matches"])
    out["feeds_searched"] = len(feed_searches)

    return jsonify(out)


def _detect_ioc_type(q):
    import re as _re
    q = q.strip()
    if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', q):         return "ip"
    if _re.match(r'^[0-9a-fA-F]{64}$', q):                              return "sha256"
    if _re.match(r'^[0-9a-fA-F]{40}$', q):                              return "sha1"
    if _re.match(r'^[0-9a-fA-F]{32}$', q):                              return "md5"
    if _re.match(r'^CVE-\d{4}-\d+$', q, _re.IGNORECASE):               return "cve"
    if _re.match(r'^https?://', q):                                      return "url"
    if _re.match(r'^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(/.*)?$', q):         return "domain"
    if "@" in q:                                                         return "email"
    return "keyword"


def _build_external_links(q):
    import urllib.parse as _up
    eq = _up.quote(q)
    links = {
        "VirusTotal":   f"https://www.virustotal.com/gui/search/{eq}",
        "Shodan":       f"https://www.shodan.io/search?query={eq}",
        "Censys":       f"https://search.censys.io/search?resource=hosts&q={eq}",
        "AbuseIPDB":    f"https://www.abuseipdb.com/check/{eq}",
        "URLScan":      f"https://urlscan.io/search/#{eq}",
        "OTX AlienVault": f"https://otx.alienvault.com/indicator/ip/{eq}",
        "GreyNoise":    f"https://viz.greynoise.io/ip/{eq}",
        "ThreatFox":    f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{eq}",
        "MalwareBazaar":f"https://bazaar.abuse.ch/browse.php?search={eq}",
    }
    # Filter to most relevant links based on IOC type
    ioc_t = _detect_ioc_type(q)
    if ioc_t == "ip":
        return {k: v for k, v in links.items()
                if k in ("VirusTotal","Shodan","AbuseIPDB","OTX AlienVault","GreyNoise","ThreatFox","Censys")}
    elif ioc_t in ("sha256","sha1","md5"):
        return {k: v for k, v in links.items()
                if k in ("VirusTotal","MalwareBazaar","OTX AlienVault","URLScan")}
    elif ioc_t in ("domain","url"):
        return {k: v for k, v in links.items()
                if k in ("VirusTotal","URLScan","OTX AlienVault","ThreatFox","Shodan")}
    elif ioc_t == "cve":
        return {
            "NVD":         f"https://nvd.nist.gov/vuln/detail/{q.upper()}",
            "CISA KEV":    f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "Exploit-DB":  f"https://www.exploit-db.com/search?cve={q.upper()}",
            "GitHub":      f"https://github.com/search?q={eq}&type=repositories",
        }
    return links



    """
    Aggregated map feed — combines all sources.
    Returns IPs with country codes where available (no geo lookup needed for those).
    Sources with country pre-populated: DShield, AbuseIPDB, Feodo
    Sources needing geo: blocklist.de, IPsum, CINS, ThreatFox, URLhaus
    """
    limit  = request.args.get("limit", 500, type=int)
    source = request.args.get("source", "all")
    out    = []

    def add(items, type_key):
        for i in items:
            if source != "all" and i.get("source","").lower().replace(" ","_") != source:
                continue
            out.append(i)

    if source in ("all", "dshield"):
        for e in get_cache("dshield")["data"]:
            out.append({"ip": e["ip"], "country": e.get("country",""),
                        "source": "DShield/SANS", "type": "scanner",
                        "note": e.get("note",""), "confidence": 85})

    if source in ("all", "abuseipdb"):
        for e in get_cache("abuseipdb")["data"]:
            out.append({"ip": e["ip"], "country": e.get("country",""),
                        "source": "AbuseIPDB", "type": "abusive",
                        "note": e.get("note",""),
                        "confidence": e.get("confidence", 90)})

    if source in ("all", "feodo"):
        for e in get_cache("feodo")["data"]:
            out.append({"ip": e["ip"], "country": e.get("country",""),
                        "source": "Feodo/Botnet", "type": "c2",
                        "note": f"Botnet C2 — {e.get('malware','')}",
                        "confidence": 95})

    if source in ("all", "threatfox"):
        for e in get_cache("threatfox")["data"]:
            ioc = e.get("ioc","")
            ip  = ioc.split(":")[0] if ":" in ioc else ioc
            if ip and ip[0].isdigit():
                out.append({"ip": ip, "country": "",
                            "source": "ThreatFox", "type": "ioc",
                            "note": e.get("malware",""), "confidence": e.get("confidence",75)})

    if source in ("all", "urlhaus"):
        for e in get_cache("urlhaus")["data"]:
            host = e.get("host","")
            if host and host[0].isdigit():
                out.append({"ip": host, "country": "",
                            "source": "URLhaus", "type": "malware_url",
                            "note": e.get("threat",""), "confidence": 80})

    if source in ("all", "blocklist_de"):
        for e in get_cache("blocklist_de")["data"]:
            out.append({"ip": e["ip"], "country": "",
                        "source": "blocklist.de", "type": "attacker",
                        "note": e.get("note",""), "confidence": 80})

    if source in ("all", "ipsum"):
        for e in get_cache("ipsum")["data"]:
            out.append({"ip": e["ip"], "country": "",
                        "source": "IPsum", "type": "blocklist",
                        "note": e.get("note",""), "confidence": 75})

    if source in ("all", "cinsscore"):
        for e in get_cache("cinsscore")["data"]:
            out.append({"ip": e["ip"], "country": "",
                        "source": "CINS Score", "type": "bad_reputation",
                        "note": e.get("note",""), "confidence": 70})

    # Shuffle for visual variety then cap
    import random
    random.shuffle(out)
    return jsonify({
        "count":   len(out),
        "capped":  min(len(out), limit),
        "data":    out[:limit],
        "sources": list({e["source"] for e in out}),
    })


@app.route("/api/map")
def api_map():
    """
    Aggregated map feed — combines all geo sources.
    Pre-geolocated: DShield, AbuseIPDB, Feodo (country code in data).
    Needs geo: ThreatFox IPs, URLhaus IPs, blocklist.de, IPsum, CINS.
    """
    limit  = request.args.get("limit", 500, type=int)
    source = request.args.get("source", "all")
    out    = []

    if source in ("all", "dshield"):
        for e in get_cache("dshield")["data"]:
            out.append({"ip": e.get("ip",""), "country": e.get("country",""),
                        "source": "DShield/SANS", "type": "scanner",
                        "note": e.get("note",""), "confidence": 85})

    if source in ("all", "abuseipdb"):
        for e in get_cache("abuseipdb")["data"]:
            out.append({"ip": e.get("ip",""), "country": e.get("country",""),
                        "source": "AbuseIPDB", "type": "abusive",
                        "note": e.get("note",""), "confidence": e.get("confidence", 90)})

    if source in ("all", "feodo"):
        for e in get_cache("feodo")["data"]:
            out.append({"ip": e.get("ip",""), "country": e.get("country",""),
                        "source": "Feodo/Botnet", "type": "c2",
                        "note": f"Botnet C2 — {e.get('malware','')}", "confidence": 95})

    if source in ("all", "threatfox"):
        for e in get_cache("threatfox")["data"]:
            ioc = e.get("ioc","")
            ip  = ioc.split(":")[0] if ":" in ioc else ioc
            if ip and ip[0:1].isdigit():
                out.append({"ip": ip, "country": "",
                            "source": "ThreatFox", "type": "ioc",
                            "note": e.get("malware",""), "confidence": e.get("confidence",75)})

    if source in ("all", "urlhaus"):
        for e in get_cache("urlhaus")["data"]:
            host = e.get("host","")
            if host and host[0:1].isdigit():
                out.append({"ip": host, "country": "",
                            "source": "URLhaus", "type": "malware_url",
                            "note": e.get("threat",""), "confidence": 80})

    if source in ("all", "blocklist_de"):
        for e in get_cache("blocklist_de")["data"]:
            out.append({"ip": e.get("ip",""), "country": "",
                        "source": "blocklist.de", "type": "attacker",
                        "note": e.get("note",""), "confidence": 80})

    if source in ("all", "ipsum"):
        for e in get_cache("ipsum")["data"]:
            out.append({"ip": e.get("ip",""), "country": "",
                        "source": "IPsum", "type": "blocklist",
                        "note": e.get("note",""), "confidence": 75})

    if source in ("all", "cinsscore"):
        for e in get_cache("cinsscore")["data"]:
            out.append({"ip": e.get("ip",""), "country": "",
                        "source": "CINS Score", "type": "bad_reputation",
                        "note": e.get("note",""), "confidence": 70})

    import random
    random.shuffle(out)
    return jsonify({
        "count":   len(out),
        "capped":  min(len(out), limit),
        "data":    out[:limit],
        "sources": list({e["source"] for e in out}),
    })


@app.route("/api/map/stats")
def api_map_stats():
    """Returns per-source counts and status for the map legend."""
    stats = {}
    source_map = {
        "DShield/SANS":  "dshield",
        "AbuseIPDB":     "abuseipdb",
        "Feodo/Botnet":  "feodo",
        "ThreatFox":     "threatfox",
        "URLhaus":       "urlhaus",
        "blocklist.de":  "blocklist_de",
        "IPsum":         "ipsum",
        "CINS Score":    "cinsscore",
    }
    for label, key in source_map.items():
        c = get_cache(key)
        stats[label] = {
            "count":   c["count"],
            "status":  c["status"],
            "updated": c["updated"],
            "note":    c.get("note",""),
        }
    return jsonify(stats)
def api_geo(ip):
    """
    Proxy single IP geolocation via ip-api.com.
    Free, no key, 45 req/min. Going through backend avoids browser CORS.
    """
    # Basic IP validation
    import re as _re
    if not _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({"error":"invalid IP"}), 400
    # Don't geolocate private/reserved ranges
    parts = [int(x) for x in ip.split('.')]
    if parts[0] in (10,127) or (parts[0]==172 and 16<=parts[1]<=31) or (parts[0]==192 and parts[1]==168):
        return jsonify({"status":"private","countryCode":"","lat":0,"lon":0})
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields":"status,country,countryCode,lat,lon,isp,org"},
            timeout=8
        )
        return jsonify(r.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 503


@app.route("/api/geo/batch", methods=["POST"])
def api_geo_batch():
    """
    Batch geolocate up to 100 IPs via ip-api.com batch endpoint.
    More efficient than individual calls.
    """
    try:
        ips = request.get_json() or []
        if not isinstance(ips, list) or len(ips) > 100:
            return jsonify({"error":"Send a JSON array of up to 100 IP strings"}), 400
        # ip-api.com batch endpoint
        r = requests.post(
            "http://ip-api.com/batch",
            json=[{"query": ip, "fields": "status,country,countryCode,lat,lon,query"}
                  for ip in ips if isinstance(ip, str)],
            timeout=15
        )
        return jsonify(r.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 503
def api_refresh(feed_name):
    fn_map = {"malware_bazaar":fetch_malware_bazaar,"urlhaus":fetch_urlhaus,
              "threatfox":fetch_threatfox,"cisa_kev":fetch_cisa_kev,
              "feodo":fetch_feodo,"ssl_blacklist":fetch_ssl_blacklist,
              "nvd_cves":fetch_nvd_cves,"mitre_attack":fetch_mitre_attack,
              "openphish":fetch_openphish,"phishtank":fetch_openphish,
              "blocklist_de":fetch_blocklist_de,"dshield":fetch_dshield,
              "ipsum":fetch_ipsum,"cinsscore":fetch_cinsscore,
              "abuseipdb":fetch_abuseipdb}
    fn = fn_map.get(feed_name)
    if not fn: return jsonify({"error":"Unknown feed"}), 404
    threading.Thread(target=fn, daemon=True).start()
    return jsonify({"message":f"Refreshing {feed_name}"})




# ══════════════════════════════════════════════════════════════════════════════
# EYES ON THE GROUND — Traffic Camera System (Road511 API)
# https://api.road511.com — one API for 10,000+ cameras across 40+ states
# Register at: https://road511.com  — add key to backend/config.json
# ══════════════════════════════════════════════════════════════════════════════

ROAD511_BASE     = "https://api.road511.com/api/v1"
ROAD511_JURISDICTIONS = [
    # Original 5
    "NY", "NJ", "TX", "OH", "PA",
    # High camera count states
    "CA", "GA", "MI",
    # Major US DOT systems
    "FL", "IL", "VA", "MD", "WA", "MN", "CO",
    "NC", "TN", "AZ", "OR", "WI", "KY", "WY",
    # Canadian province
    "ON",
]

# Per-jurisdiction cache — built from ROAD511_JURISDICTIONS list
camera_cache = {j: {"data": [], "status": "pending", "updated": None, "count": 0}
                for j in ROAD511_JURISDICTIONS}
camera_lock  = threading.Lock()


def set_camera_cache(jurisdiction, data, status="ok"):
    with camera_lock:
        camera_cache[jurisdiction].update(
            data=data, status=status,
            updated=datetime.now(timezone.utc).isoformat(),
            count=len(data)
        )
    log.info(f"[cameras:{jurisdiction}] {len(data)} cameras — {status}")


def fetch_cameras_jurisdiction(jurisdiction):
    """Fetch all cameras for one jurisdiction from Road511."""
    key = CONFIG.get("ROAD511_API_KEY", "").strip()
    if not key:
        set_camera_cache(jurisdiction, [], "needs_key")
        return

    cameras = []
    page    = 1
    limit   = 200

    try:
        while True:
            r = requests.get(
                f"{ROAD511_BASE}/features",
                headers={"X-API-Key": key, "Accept": "application/json"},
                params={
                    "type":         "cameras",
                    "jurisdiction": jurisdiction,
                    "limit":        limit,
                    "page":         page,
                },
                timeout=30
            )
            if r.status_code == 401:
                log.warning(f"[cameras:{jurisdiction}] Invalid API key")
                set_camera_cache(jurisdiction, [], "invalid_key")
                return
            if r.status_code == 429:
                log.warning(f"[cameras:{jurisdiction}] Rate limited")
                set_camera_cache(jurisdiction, cameras or [], "rate_limited")
                return
            r.raise_for_status()
            payload = r.json()
            batch   = payload.get("data", [])
            if not batch:
                break

            for cam in batch:
                props = cam.get("properties", {})
                entry = {
                    "id":          cam.get("id", ""),
                    "state":       jurisdiction,
                    "name":        cam.get("name", ""),
                    "road":        props.get("highway") or props.get("road") or "",
                    "direction":   props.get("direction", ""),
                    "lat":         float(cam.get("latitude",  0)),
                    "lon":         float(cam.get("longitude", 0)),
                    "image_url":   props.get("image_url", ""),
                    "video_url":   props.get("video_url", ""),
                    "disabled":    not cam.get("is_active", True),
                }
                if entry["lat"] and entry["lon"]:
                    cameras.append(entry)

            if not payload.get("has_more", False):
                break
            page += 1

        set_camera_cache(jurisdiction, cameras)

    except Exception as e:
        log.warning(f"[cameras:{jurisdiction}] {e}")
        set_camera_cache(jurisdiction, cameras or [], "error")


def fetch_all_cameras():
    """Refresh all jurisdictions — runs in parallel threads."""
    key = CONFIG.get("ROAD511_API_KEY", "").strip()
    if not key:
        for j in ROAD511_JURISDICTIONS:
            set_camera_cache(j, [], "needs_key")
        log.info("[cameras] No Road511 API key — add ROAD511_API_KEY to config.json")
        return
    threads = []
    for j in ROAD511_JURISDICTIONS:
        t = threading.Thread(target=fetch_cameras_jurisdiction, args=(j,), daemon=True)
        t.start()
        threads.append(t)
    # Don't block — threads run independently


# ── Image proxy — serves DOT camera images through backend to avoid CORS ───────
@app.route("/api/cameras/image")
def camera_image_proxy():
    """
    Proxy a camera JPEG/PNG through the backend to avoid CORS blocks.
    Usage: GET /api/cameras/image?url=<encoded_camera_image_url>
    Road511's image_url values point to official DOT servers which
    often reject direct browser requests.
    """
    from flask import Response
    img_url = request.args.get("url", "").strip()
    if not img_url:
        return "Missing url param", 400

    # Security: must be http/https and must not target private/internal IPs (SSRF guard).
    # The Road511 API key is the real authentication gate — we trust URLs it returns.
    try:
        parsed = urlparse(img_url)
        if parsed.scheme not in ("http", "https"):
            return "Only http/https URLs allowed", 400
        host = parsed.netloc.lower().split(":")[0]
        import ipaddress
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return "Private IP not allowed", 403
        except ValueError:
            pass  # It's a hostname, not a bare IP — fine
        # Catch obvious localhost variants by name
        if host in ("localhost", "::1") or host.endswith(".local"):
            return "Local host not allowed", 403
    except Exception:
        return "Invalid URL", 400

    try:
        resp = requests.get(
            img_url,
            timeout=10,
            headers={
                "User-Agent": "TOOB-OSINT/2.5 Traffic Camera Viewer",
                "Referer":    "https://road511.com/",
                "Accept":     "image/jpeg,image/png,image/*,*/*",
            },
            stream=True
        )
        if resp.status_code != 200:
            return f"Upstream {resp.status_code}", 502

        content_type = resp.headers.get("Content-Type", "image/jpeg")
        out = Response(resp.content, content_type=content_type)
        out.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        out.headers["Pragma"]        = "no-cache"
        out.headers["Expires"]       = "0"
        return out
    except requests.exceptions.Timeout:
        return "Camera timeout", 504
    except Exception as e:
        log.warning(f"[cam_proxy] {img_url[:70]} → {e}")
        return "Proxy error", 503


# ── Camera API routes ──────────────────────────────────────────────────────────
@app.route("/api/cameras")
def api_cameras():
    """
    Return cameras, optionally filtered by jurisdiction.
    Query: state=NY|NJ|TX|OH|PA|ALL  (default ALL)
    """
    state_filter = request.args.get("state", "ALL").upper()
    with camera_lock:
        if state_filter == "ALL":
            all_cams    = []
            states_meta = {}
            for j, data in camera_cache.items():
                all_cams.extend(data["data"])
                states_meta[j] = {
                    "count":   data["count"],
                    "status":  data["status"],
                    "updated": data["updated"],
                }
            return jsonify({"cameras": all_cams, "states": states_meta,
                            "total": len(all_cams)})

        if state_filter in camera_cache:
            data = camera_cache[state_filter]
            return jsonify({
                "cameras": data["data"],
                "states":  {state_filter: {"count":   data["count"],
                                           "status":  data["status"],
                                           "updated": data["updated"]}},
                "total":   data["count"],
            })
        return jsonify({"error": f"Unknown state: {state_filter}"}), 400


@app.route("/api/cameras/status")
def api_cameras_status():
    with camera_lock:
        return jsonify({
            j: {"count": v["count"], "status": v["status"], "updated": v["updated"]}
            for j, v in camera_cache.items()
        })


@app.route("/api/cameras/refresh", methods=["POST"])
@app.route("/api/cameras/refresh/<state>", methods=["POST"])
def api_cameras_refresh(state=None):
    """Trigger an immediate camera refresh. state=None refreshes all."""
    key = CONFIG.get("ROAD511_API_KEY", "").strip()
    if not key:
        return jsonify({"error": "No ROAD511_API_KEY configured"}), 400

    if state:
        j = state.upper()
        if j not in ROAD511_JURISDICTIONS:
            return jsonify({"error": f"Unknown jurisdiction: {j}"}), 404
        threading.Thread(target=fetch_cameras_jurisdiction, args=(j,), daemon=True).start()
        return jsonify({"message": f"Refreshing {j} cameras"})
    else:
        threading.Thread(target=fetch_all_cameras, daemon=True).start()
        return jsonify({"message": "Refreshing all camera jurisdictions"})


# ── Startup loader ─────────────────────────────────────────────────────────────
def init_camera_feeds():
    """Called once at startup — kicks off background fetches."""
    key = CONFIG.get("ROAD511_API_KEY", "").strip()
    if key:
        log.info("[cameras] Road511 key found — loading all jurisdictions")
        threading.Thread(target=fetch_all_cameras, daemon=True).start()
    else:
        for j in ROAD511_JURISDICTIONS:
            set_camera_cache(j, [], "needs_key")
        log.info("[cameras] No ROAD511_API_KEY — add it to backend/config.json")


# ── Scheduler ─────────────────────────────────────────────────────────────────
def start_scheduler():
    from apscheduler.executors.pool import ThreadPoolExecutor as APThreadPool
    executors = {"default": APThreadPool(max_workers=6)}
    s   = BackgroundScheduler(daemon=True, executors=executors)
    now = datetime.now()

    # Stagger startup times so fetchers don't all hammer the network simultaneously.
    # Fast public feeds first, slow/key-dependent ones spread out over ~2 minutes.
    def t(seconds): return now + timedelta(seconds=seconds)

    s.add_job(fetch_feodo,          "interval", minutes=30,  id="feodo",  next_run_time=t(2))
    s.add_job(fetch_ssl_blacklist,  "interval", minutes=30,  id="ssl",    next_run_time=t(5))
    s.add_job(fetch_dshield,        "interval", minutes=15,  id="dsh",    next_run_time=t(8))
    s.add_job(fetch_blocklist_de,   "interval", minutes=30,  id="blde",   next_run_time=t(12))
    s.add_job(fetch_openphish,      "interval", hours=12,    id="phish",  next_run_time=t(16))
    s.add_job(fetch_cinsscore,      "interval", hours=1,     id="cins",   next_run_time=t(20))
    s.add_job(fetch_ipsum,          "interval", hours=6,     id="ipsum",  next_run_time=t(25))
    s.add_job(fetch_malware_bazaar, "interval", minutes=10,  id="mb",     next_run_time=t(30))
    s.add_job(fetch_urlhaus,        "interval", minutes=10,  id="uh",     next_run_time=t(40))
    s.add_job(fetch_threatfox,      "interval", minutes=15,  id="tf",     next_run_time=t(50))
    s.add_job(fetch_nvd_cves,       "interval", hours=2,     id="nvd",    next_run_time=t(60))
    s.add_job(fetch_cisa_kev,       "interval", hours=6,     id="kev",    next_run_time=t(75))
    s.add_job(fetch_mitre_attack,   "interval", hours=6,     id="mitre",  next_run_time=t(90))
    # AbuseIPDB: delay 1 hour to avoid burning daily rate limit on restarts
    s.add_job(fetch_abuseipdb,      "interval", hours=1,     id="abuse",
              next_run_time=now + timedelta(hours=1))
    # Camera refresh every 30 min — initial load handled by init_camera_feeds()
    s.add_job(fetch_all_cameras,    "interval", minutes=30,  id="cameras",
              next_run_time=now + timedelta(minutes=30))
    s.start()
    log.info("Scheduler started — feeds staggered over ~90s startup window")
    return s


if __name__ == "__main__":
    log.info("="*58)
    log.info("  The Open OSINT Board Backend v2.5")
    log.info("  Cameras: Road511 API (api.road511.com)")
    log.info("  Jurisdictions: NY, NJ, TX, OH, PA")
    log.info("  Add ROAD511_API_KEY to backend/config.json")
    log.info("  Threat feeds: abuse.ch, CISA, NVD, MITRE, AbuseIPDB")
    log.info("="*58)
    _preload_abuseipdb_index()
    _preload_phishing_cache()
    init_camera_feeds()
    start_scheduler()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
