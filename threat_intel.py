"""
Threat Intelligence Module — Industry-grade.
Provides IP reputation, geo-location, MITRE ATT&CK mapping,
and optional external API integration (AbuseIPDB, VirusTotal).
All external lookups are cached in SQLite to avoid rate limits.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional

import config
from data_store import DataStore

logger = logging.getLogger("threat_intel")

# ============================================================
# MITRE ATT&CK Technique Mapping
# ============================================================
MITRE_ATTACK_MAP: Dict[str, Dict] = {
    "C2 Server":              {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    "Data Exfiltration":      {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "Scanner":                {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    "Botnet Node":            {"id": "T1583", "name": "Acquire Infrastructure", "tactic": "Resource Development"},
    "Malware Distribution":   {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "Tor Exit Node":          {"id": "T1090", "name": "Proxy", "tactic": "Command and Control"},
    "Security Scanner":       {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "Ransomware C2":          {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
    "Credential Harvester":   {"id": "T1555", "name": "Credentials from Password Stores", "tactic": "Credential Access"},
}

# ============================================================
# GEO COORDINATE DATABASE
# ============================================================
GEO_DATABASE: Dict[str, Dict] = {
    "203.0.113.42":  {"lat": 55.75,  "lng": 37.62,   "city": "Moscow",        "country": "Russia"},
    "203.0.113.45":  {"lat": 39.90,  "lng": 116.40,  "city": "Beijing",       "country": "China"},
    "198.51.100.23": {"lat": 28.61,  "lng": 77.21,   "city": "New Delhi",     "country": "India"},
    "198.51.100.42": {"lat": -33.87, "lng": 151.21,  "city": "Sydney",        "country": "Australia"},
    "198.51.100.10": {"lat": 35.69,  "lng": 139.69,  "city": "Tokyo",         "country": "Japan"},
    "192.0.2.100":   {"lat": 51.51,  "lng": -0.13,   "city": "London",        "country": "UK"},
    "8.8.8.8":       {"lat": 37.39,  "lng": -122.08, "city": "Mountain View", "country": "USA"},
    "8.8.4.4":       {"lat": 37.39,  "lng": -122.08, "city": "Mountain View", "country": "USA"},
    "1.1.1.1":       {"lat": -33.87, "lng": 151.21,  "city": "Sydney",        "country": "Australia"},
    "1.0.0.1":       {"lat": -33.87, "lng": 151.21,  "city": "Sydney",        "country": "Australia"},
    "45.33.32.156":  {"lat": 47.61,  "lng": -122.33, "city": "Seattle",       "country": "USA"},
    "185.220.101.1": {"lat": 52.52,  "lng": 13.41,   "city": "Berlin",        "country": "Germany"},
    "91.219.236.2":  {"lat": 59.33,  "lng": 18.07,   "city": "Stockholm",     "country": "Sweden"},
    "177.54.150.10": {"lat": -23.55, "lng": -46.63,  "city": "São Paulo",     "country": "Brazil"},
    "41.231.21.5":   {"lat": 36.81,  "lng": 10.17,   "city": "Tunis",         "country": "Tunisia"},
    "156.154.70.1":  {"lat": 40.71,  "lng": -74.01,  "city": "New York",      "country": "USA"},
    "5.188.206.23":  {"lat": 60.17,  "lng": 24.94,   "city": "Helsinki",      "country": "Finland"},
    "45.142.212.100":{"lat": 52.37,  "lng": 4.90,    "city": "Amsterdam",     "country": "Netherlands"},
    "194.165.16.77": {"lat": 48.21,  "lng": 16.37,   "city": "Vienna",        "country": "Austria"},
    "92.63.197.153": {"lat": 50.45,  "lng": 30.52,   "city": "Kyiv",          "country": "Ukraine"},
    "185.234.219.10":{"lat": 41.01,  "lng": 28.97,   "city": "Istanbul",      "country": "Turkey"},
}

VM_LOCATION = {"lat": 28.61, "lng": 77.21, "city": "Local Network", "country": "India"}

# ============================================================
# THREAT INTELLIGENCE DATABASE (Local)
# ============================================================
THREAT_DATABASE: Dict[str, Dict] = {
    "203.0.113.42":   {"risk_score": 95, "category": "C2 Server",            "threat_type": "Command & Control",     "malware_family": "Cobalt Strike",      "first_seen": "2025-08-15", "reports": 342,  "tags": ["APT", "C2", "Backdoor"]},
    "203.0.113.45":   {"risk_score": 88, "category": "Data Exfiltration",    "threat_type": "Exfil Endpoint",        "malware_family": "Custom Stealer",     "first_seen": "2025-11-02", "reports": 156,  "tags": ["Stealer", "Exfil", "APT29"]},
    "198.51.100.23":  {"risk_score": 72, "category": "Scanner",              "threat_type": "Reconnaissance",        "malware_family": "Masscan Bot",        "first_seen": "2025-06-20", "reports": 891,  "tags": ["Scanner", "Recon", "Brute-force"]},
    "198.51.100.42":  {"risk_score": 98, "category": "C2 Server",            "threat_type": "Metasploit Handler",    "malware_family": "Meterpreter",        "first_seen": "2025-03-10", "reports": 1204, "tags": ["Metasploit", "C2", "Reverse Shell"]},
    "198.51.100.10":  {"risk_score": 65, "category": "Botnet Node",          "threat_type": "DDoS Botnet",           "malware_family": "Mirai Variant",      "first_seen": "2025-09-30", "reports": 567,  "tags": ["Botnet", "DDoS", "IoT"]},
    "192.0.2.100":    {"risk_score": 80, "category": "Malware Distribution", "threat_type": "Dropper Server",        "malware_family": "Emotet",             "first_seen": "2025-07-14", "reports": 723,  "tags": ["Dropper", "Emotet", "Phishing"]},
    "185.220.101.1":  {"risk_score": 45, "category": "Tor Exit Node",        "threat_type": "Anonymization",        "malware_family": "N/A",               "first_seen": "2024-01-01", "reports": 2100, "tags": ["Tor", "Anonymizer", "Privacy"]},
    "45.33.32.156":   {"risk_score": 30, "category": "Security Scanner",     "threat_type": "Nmap Scanner",          "malware_family": "N/A",               "first_seen": "2024-06-01", "reports": 50,   "tags": ["Nmap", "Scanner", "Legitimate"]},
    "5.188.206.23":   {"risk_score": 92, "category": "Ransomware C2",        "threat_type": "Ransomware Handler",    "malware_family": "LockBit 3.0",        "first_seen": "2025-12-01", "reports": 890,  "tags": ["Ransomware", "LockBit", "APT"]},
    "45.142.212.100": {"risk_score": 87, "category": "Credential Harvester", "threat_type": "Phishing Infrastructure","malware_family": "AsyncRAT",          "first_seen": "2025-10-15", "reports": 445,  "tags": ["Phishing", "AsyncRAT", "Credential"]},
    "92.63.197.153":  {"risk_score": 79, "category": "C2 Server",            "threat_type": "Remote Access Trojan",  "malware_family": "NjRAT",             "first_seen": "2025-05-20", "reports": 312,  "tags": ["RAT", "C2", "Persistence"]},
}


# ============================================================
# External API Lookups (AbuseIPDB + VirusTotal)
# ============================================================

def _lookup_abuseipdb(ip: str) -> Optional[Dict]:
    """Query AbuseIPDB for real-time IP reputation."""
    if not config.ABUSEIPDB_API_KEY:
        return None
    try:
        import requests  # type: ignore[import]
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "risk_score":     data.get("abuseConfidenceScore", 0),
                "category":       "AbuseIPDB — " + (data.get("usageType") or "Unknown"),
                "threat_type":    "External Reputation",
                "malware_family": "N/A",
                "first_seen":     data.get("lastReportedAt", "N/A"),
                "reports":        data.get("totalReports", 0),
                "tags":           ["AbuseIPDB", data.get("countryCode", "")],
                "source":         "AbuseIPDB",
            }
    except Exception as exc:
        logger.debug("AbuseIPDB lookup error for %s: %s", ip, exc)
    return None


def _lookup_virustotal_hash(sha256: str) -> Optional[Dict]:
    """Query VirusTotal for a file hash."""
    if not config.VIRUSTOTAL_API_KEY:
        return None
    try:
        import requests  # type: ignore[import]
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
            timeout=8,
        )
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total     = sum(stats.values()) or 1
            return {
                "sha256":         sha256,
                "malicious":      malicious,
                "total_engines":  total,
                "detection_rate": f"{malicious}/{total}",
                "verdict":        "MALICIOUS" if malicious > 3 else "CLEAN" if malicious == 0 else "SUSPICIOUS",
                "source":         "VirusTotal",
            }
    except Exception as exc:
        logger.debug("VirusTotal lookup error for %s: %s", sha256, exc)
    return None


# ============================================================
# Public API
# ============================================================

def get_ip_geo(ip: str) -> Optional[Dict]:
    return GEO_DATABASE.get(ip)


def get_ip_threat_info(ip: str) -> Optional[Dict]:
    return THREAT_DATABASE.get(ip)


def get_ip_risk_score(ip: str) -> int:
    info = THREAT_DATABASE.get(ip)
    if info:
        return info["risk_score"]
    if not ip.startswith(("192.168.", "10.", "172.16.", "127.")):
        return 40
    return 0


def lookup_ip(ip: str) -> Dict:
    """
    Full IP lookup: local DB → SQLite cache → AbuseIPDB (if API key set).
    Always returns a dict, even for unknown IPs.
    Adds MITRE ATT&CK mapping.
    """
    is_private = ip.startswith(("192.168.", "10.", "172.16.", "172.17.",
                                "172.18.", "172.19.", "172.2", "172.3",
                                "127.", "0.0.0.0", "255."))
    geo    = get_ip_geo(ip) or {}
    threat = get_ip_threat_info(ip)

    # Try SQLite cache first
    store  = DataStore()
    cached = store.get_cached_threat_intel(ip)
    if cached:
        threat = cached

    # Fall back to AbuseIPDB for unknown external IPs
    if not threat and not is_private and config.ABUSEIPDB_API_KEY:
        live = _lookup_abuseipdb(ip)
        if live:
            threat = live
            store.cache_threat_intel(ip, live)
            logger.info("AbuseIPDB result cached for %s (score=%s)", ip, live.get("risk_score"))

    threat = threat or {}
    category = threat.get("category", "Unknown" if not is_private else "Internal")
    mitre = MITRE_ATTACK_MAP.get(category, {})

    return {
        "ip":         ip,
        "is_private": is_private,
        "geo": {
            "lat":     geo.get("lat", 0),
            "lng":     geo.get("lng", 0),
            "city":    geo.get("city", "Unknown"),
            "country": geo.get("country", "Unknown"),
        },
        "threat": {
            "risk_score":     threat.get("risk_score", 40 if not is_private else 0),
            "category":       category,
            "threat_type":    threat.get("threat_type", "Unclassified"),
            "malware_family": threat.get("malware_family", "N/A"),
            "first_seen":     threat.get("first_seen", "N/A"),
            "reports":        threat.get("reports", 0),
            "tags":           threat.get("tags", []),
            "source":         threat.get("source", "Local DB"),
        },
        "mitre": mitre,
    }


def lookup_file_hash(sha256: str) -> Optional[Dict]:
    """
    Lookup a file hash against VirusTotal (if API key configured).
    Results are cached in SQLite.
    """
    if not sha256:
        return None
    store  = DataStore()
    cached = store.get_cached_threat_intel(f"hash:{sha256}")
    if cached:
        return cached
    result = _lookup_virustotal_hash(sha256)
    if result:
        store.cache_threat_intel(f"hash:{sha256}", result)
    return result


def get_all_known_threats() -> List[Dict]:
    results = [lookup_ip(ip) for ip in THREAT_DATABASE]
    return sorted(results, key=lambda x: x["threat"]["risk_score"], reverse=True)


def get_geo_for_connections(ip_list: List[str]) -> List[Dict]:
    connections = []
    for ip in ip_list:
        geo = get_ip_geo(ip)
        if geo:
            threat = get_ip_threat_info(ip)
            connections.append({
                "ip":         ip,
                "lat":        geo["lat"],
                "lng":        geo["lng"],
                "city":       geo["city"],
                "country":    geo["country"],
                "risk_score": threat["risk_score"] if threat else 40,
                "category":   threat["category"]   if threat else "Unknown",
                "vm_lat":     VM_LOCATION["lat"],
                "vm_lng":     VM_LOCATION["lng"],
            })
    return connections
