"""
Configuration module for VM Introspection Security System.
Industry-grade: loads settings from environment / .env file with sensible defaults.
Uses psutil to auto-detect the active network interface.
"""

import os
import logging
import psutil

# Load .env file if present (python-dotenv)
try:
    from dotenv import load_dotenv  # type: ignore[import]
    load_dotenv()
except ImportError:
    pass  # dotenv is optional; fall back to environment variables


# ============================================================
# ORGANISATION METADATA
# ============================================================
ORG_NAME        = os.environ.get("ORG_NAME",       "My Organisation")
ANALYST_NAME    = os.environ.get("ANALYST_NAME",   "Security Analyst")
DEPLOYMENT_ID   = os.environ.get("DEPLOYMENT_ID",  "VM-SEC-001")


# ============================================================
# LOGGING CONFIGURATION
# ============================================================
LOG_LEVEL   = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FILE    = os.environ.get("LOG_FILE",  os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "system.log"
))

# Configure root logger once at import time
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)

logger = logging.getLogger("config")


# ============================================================
# NETWORK MONITORING CONFIGURATION
# ============================================================

def _auto_detect_interface() -> str:
    """
    Auto-detect the primary active network interface using psutil.
    Prefers interfaces that have an IPv4 address and are not loopback.
    Falls back to 'eth0' if nothing is found.
    """
    preferred_names = ["Wi-Fi", "Ethernet", "eth0", "en0", "wlan0", "wlan1", "enp0s3", "ens33"]
    try:
        stats     = psutil.net_if_stats()
        addresses = psutil.net_if_addrs()

        # First preference: an interface that is up and has an IPv4 address
        for name in preferred_names:
            if name in stats and stats[name].isup and name in addresses:
                for addr in addresses[name]:
                    if addr.family == 2:  # AF_INET (IPv4)
                        logger.info("Auto-detected network interface: %s", name)
                        return name

        # Second preference: any interface that is up and has an IPv4 address
        for name, st in stats.items():
            if st.isup and name != "Loopback Pseudo-Interface 1" and name.lower() != "lo":
                if name in addresses:
                    for addr in addresses[name]:
                        if addr.family == 2:
                            logger.info("Auto-detected network interface: %s", name)
                            return name
    except Exception as exc:
        logger.warning("Interface auto-detection failed: %s", exc)

    fallback = os.environ.get("VM_MONITOR_IFACE", "eth0")
    logger.warning("Could not auto-detect interface, using: %s", fallback)
    return fallback


# Network interface: env var overrides auto-detection
NETWORK_INTERFACE: str = os.environ.get("VM_MONITOR_IFACE") or _auto_detect_interface()

# VM IP address (the monitored machine's IP on the network)
VM_IP: str = os.environ.get("VM_IP", "192.168.1.100")

# Known safe/trusted IPs
TRUSTED_IPS: list = [
    "192.168.1.1",
    "192.168.1.0",
    "255.255.255.255",
    "0.0.0.0",
    VM_IP,
]

# Promiscuous capture: capture ALL traffic on the interface (like Wireshark)
# Set to False to capture only traffic matching VM_IP
PROMISCUOUS_CAPTURE: bool = os.environ.get("PROMISCUOUS_CAPTURE", "true").lower() == "true"

# Suspicious ports commonly used by malware
SUSPICIOUS_PORTS: list = [
    4444, 5555, 1337, 31337,
    8080, 6666, 6667, 9999,
    12345, 54321, 3389, 445,
    135, 1234, 27374, 65000,
]

# Beaconing detection thresholds
BEACON_THRESHOLD:    int = int(os.environ.get("BEACON_THRESHOLD",    "5"))
BEACON_TIME_WINDOW:  int = int(os.environ.get("BEACON_TIME_WINDOW",  "60"))


# ============================================================
# FILE MONITORING CONFIGURATION
# ============================================================
SHARED_FOLDER_PATH: str = os.environ.get(
    "VM_SHARED_FOLDER",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "shared_folder")
)

SUSPICIOUS_EXTENSIONS: list = [
    ".exe", ".bat", ".ps1", ".sh", ".cmd", ".vbs",
    ".js", ".wsf", ".scr", ".pif", ".msi", ".dll",
    ".hta", ".cpl", ".reg", ".inf", ".lnk", ".jar",
    ".py", ".rb", ".pl", ".php",  # script languages
]

# File entropy threshold: files with entropy > this are possibly encrypted/packed
HIGH_ENTROPY_THRESHOLD: float = float(os.environ.get("HIGH_ENTROPY_THRESHOLD", "7.0"))


# ============================================================
# MEMORY / CPU MONITORING CONFIGURATION
# ============================================================
MEMORY_WARNING_THRESHOLD:  int = int(os.environ.get("MEMORY_WARNING_THRESHOLD",  "75"))
MEMORY_CRITICAL_THRESHOLD: int = int(os.environ.get("MEMORY_CRITICAL_THRESHOLD", "90"))
CPU_WARNING_THRESHOLD:     int = int(os.environ.get("CPU_WARNING_THRESHOLD",      "80"))
CPU_CRITICAL_THRESHOLD:    int = int(os.environ.get("CPU_CRITICAL_THRESHOLD",     "95"))

# Monitoring interval (seconds)
RESOURCE_MONITOR_INTERVAL: int = int(os.environ.get("RESOURCE_MONITOR_INTERVAL", "1"))

# How many top processes to track
TOP_PROCESS_COUNT: int = int(os.environ.get("TOP_PROCESS_COUNT", "10"))


# ============================================================
# BEHAVIORAL ANALYZER CONFIGURATION
# ============================================================
THREAT_SAFE_THRESHOLD:     int = int(os.environ.get("THREAT_SAFE_THRESHOLD",     "25"))
THREAT_WARNING_THRESHOLD:  int = int(os.environ.get("THREAT_WARNING_THRESHOLD",  "50"))
THREAT_CRITICAL_THRESHOLD: int = int(os.environ.get("THREAT_CRITICAL_THRESHOLD", "75"))
ANOMALY_DECAY_RATE:        int = int(os.environ.get("ANOMALY_DECAY_RATE",        "5"))


# ============================================================
# THREAT INTELLIGENCE — EXTERNAL API KEYS (OPTIONAL)
# ============================================================
ABUSEIPDB_API_KEY:  str = os.environ.get("ABUSEIPDB_API_KEY",  "")
VIRUSTOTAL_API_KEY: str = os.environ.get("VIRUSTOTAL_API_KEY", "")

# How long to cache external API results (seconds)
THREAT_INTEL_CACHE_TTL: int = int(os.environ.get("THREAT_INTEL_CACHE_TTL", "3600"))


# ============================================================
# DATA STORAGE CONFIGURATION
# ============================================================
DATA_DIR:     str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_FILE:      str = os.path.join(DATA_DIR, "security.db")   # SQLite database
LOGS_FILE:    str = os.path.join(DATA_DIR, "logs.json")     # Legacy JSON export
ALERTS_FILE:  str = os.path.join(DATA_DIR, "alerts.json")
TIMELINE_FILE: str = os.path.join(DATA_DIR, "timeline.json")

# Data retention: keep logs for this many days (0 = keep forever)
DATA_RETENTION_DAYS: int = int(os.environ.get("DATA_RETENTION_DAYS", "30"))

MAX_LOG_ENTRIES:   int = int(os.environ.get("MAX_LOG_ENTRIES",   "50000"))
MAX_ALERT_ENTRIES: int = int(os.environ.get("MAX_ALERT_ENTRIES", "5000"))


# ============================================================
# API CONFIGURATION
# ============================================================
API_HOST: str = os.environ.get("API_HOST", "0.0.0.0")
API_PORT: int = int(os.environ.get("API_PORT", "8000"))

# Optional API key for securing dashboard↔API communication (empty = no auth)
API_SECRET_KEY: str = os.environ.get("API_SECRET_KEY", "")


# ============================================================
# DASHBOARD CONFIGURATION
# ============================================================
DASHBOARD_REFRESH_INTERVAL: int = int(os.environ.get("DASHBOARD_REFRESH_INTERVAL", "2"))

os.makedirs(DATA_DIR, exist_ok=True)
logger.info("Configuration loaded — Interface: %s, VM IP: %s, Org: %s",
            NETWORK_INTERFACE, VM_IP, ORG_NAME)
