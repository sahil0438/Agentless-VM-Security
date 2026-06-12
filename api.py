"""
FastAPI Backend — Industry-grade REST API for VM Introspection Security System.

Endpoints:
  GET  /health                 — Health check
  GET  /dashboard-data         — Aggregated data for Streamlit (single request)
  GET  /status                 — Current system status
  GET  /events                 — Recent log events (paginated, filterable)
  GET  /alerts                 — Recent alerts (filterable by severity/type)
  GET  /timeline               — Attack timeline
  GET  /metrics                — Detailed metrics with history
  GET  /geo/connections        — Geo-located IP connections
  GET  /threat-intel           — Local threat intelligence DB
  GET  /threat-intel/{ip}      — Single IP lookup (live AbuseIPDB if configured)
  GET  /system/info            — Host system information (OS, interfaces, uptime)
  GET  /export/logs            — Export logs as JSON
  GET  /export/alerts          — Export alerts as JSON
  GET  /report                 — Full security report
  POST /pentest/{scenario}     — Trigger penetration-testing scenario
  POST /system/reset           — Reset all data
  POST /analyst/note           — Add an analyst investigation note
  GET  /analyst/notes          — Retrieve analyst notes
"""

import json
import logging
import os
import platform
import threading
import time
import random
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import psutil
from fastapi import FastAPI, Query, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import config
from data_store import DataStore
from network_monitor import NetworkMonitor
from file_monitor import FileMonitor
from memory_monitor import MemoryMonitor
from behavioral_analyzer import BehavioralAnalyzer
from threat_intel import (
    lookup_ip, lookup_file_hash,
    get_all_known_threats, get_geo_for_connections,
    VM_LOCATION,
)

logger = logging.getLogger("api")

# ============================================================
# Monitoring singletons
# ============================================================
store              = DataStore()
network_monitor    = NetworkMonitor()
file_monitor       = FileMonitor()
memory_monitor     = MemoryMonitor()
behavioral_analyzer = BehavioralAnalyzer()

_startup_time = datetime.now()


# ============================================================
# Lifespan: start/stop all monitors
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[type-arg]
    logger.info("=" * 60)
    logger.info("  VM INTROSPECTION SECURITY SYSTEM — STARTING")
    logger.info("  Org: %s  |  Deployment: %s", config.ORG_NAME, config.DEPLOYMENT_ID)
    logger.info("=" * 60)

    network_monitor.start()
    file_monitor.start()
    memory_monitor.start()
    behavioral_analyzer.start()

    store.add_timeline_event("SYSTEM", "VM Security System started", "INFO")
    logger.info("All modules started. API ready at http://%s:%s", config.API_HOST, config.API_PORT)

    yield  # ← application runs here

    logger.info("Shutting down all monitors...")
    network_monitor.stop()
    file_monitor.stop()
    memory_monitor.stop()
    behavioral_analyzer.stop()
    store.persist_all()
    logger.info("All modules stopped. Data persisted.")


# ============================================================
# FastAPI app
# ============================================================

app = FastAPI(
    title="VM Introspection Security API",
    description=(
        "Industry-grade agentless behavioral monitoring system for virtual machines. "
        f"Org: {config.ORG_NAME} | Deployment: {config.DEPLOYMENT_ID}"
    ),
    version="3.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Optional API-key auth helper
# ============================================================

def _check_auth(x_api_key: Optional[str]) -> None:
    """Validate API key if one is configured in .env."""
    if config.API_SECRET_KEY and x_api_key != config.API_SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ============================================================
# System info helper
# ============================================================

def _get_system_info() -> dict:
    uptime_sec = int((datetime.now() - _startup_time).total_seconds())
    ifaces = {}
    for name, addrs in psutil.net_if_addrs().items():
        ifaces[name] = [a.address for a in addrs if a.family == 2]  # IPv4 only

    return {
        "hostname":         platform.node(),
        "os":               f"{platform.system()} {platform.release()}",
        "cpu_count":        psutil.cpu_count(logical=True),
        "total_memory_gb":  round(psutil.virtual_memory().total / (1024**3), 2),
        "network_interfaces": ifaces,
        "active_interface": config.NETWORK_INTERFACE,
        "monitoring_ip":    config.VM_IP,
        "org_name":         config.ORG_NAME,
        "analyst":          config.ANALYST_NAME,
        "deployment_id":    config.DEPLOYMENT_ID,
        "uptime_seconds":   uptime_sec,
        "started_at":       _startup_time.isoformat(),
    }


# ============================================================
# Standard endpoints
# ============================================================

@app.get("/health", tags=["System"])
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.get("/system/info", tags=["System"])
async def get_system_info(x_api_key: Optional[str] = Header(default=None)):
    _check_auth(x_api_key)
    return _get_system_info()


@app.get("/status", tags=["Status"])
async def get_status():
    metrics = store.get_metrics()
    return {
        "status":            metrics.get("status", "SAFE"),
        "threat_score":      metrics.get("threat_score", 0),
        "anomaly_score":     metrics.get("anomaly_score", 0),
        "total_packets":     metrics.get("total_packets", 0),
        "packets_per_sec":   metrics.get("packets_per_sec", 0),
        "suspicious_events": metrics.get("suspicious_events", 0),
        "unique_ips":        metrics.get("unique_ips", 0),
        "memory_usage":      metrics.get("memory_usage", 0),
        "cpu_usage":         metrics.get("cpu_usage", 0),
        "disk_read_bps":     metrics.get("disk_read_bps", 0),
        "disk_write_bps":    metrics.get("disk_write_bps", 0),
        "net_bytes_sent":    metrics.get("net_bytes_sent", 0),
        "net_bytes_recv":    metrics.get("net_bytes_recv", 0),
        "protocol_counts":   metrics.get("protocol_counts", {}),
        "timestamp":         datetime.now().isoformat(),
    }


@app.get("/events", tags=["Events"])
async def get_events(
    limit:       int            = Query(default=100, ge=1, le=5000),
    log_type:    Optional[str]  = Query(default=None),
    since_hours: Optional[int]  = Query(default=None),
):
    logs = store.get_logs(limit=limit, log_type=log_type, since_hours=since_hours)
    return {"count": len(logs), "events": logs, "timestamp": datetime.now().isoformat()}


@app.get("/alerts", tags=["Alerts"])
async def get_alerts(
    limit:       int            = Query(default=50, ge=1, le=500),
    severity:    Optional[str]  = Query(default=None),
    since_hours: Optional[int]  = Query(default=None),
):
    alerts = store.get_alerts(limit=limit, severity=severity, since_hours=since_hours)
    return {"count": len(alerts), "alerts": alerts, "timestamp": datetime.now().isoformat()}


@app.get("/timeline", tags=["Timeline"])
async def get_timeline(limit: int = Query(default=100, ge=1, le=500)):
    timeline = store.get_timeline(limit=limit)
    return {"count": len(timeline), "timeline": timeline, "timestamp": datetime.now().isoformat()}


@app.get("/metrics", tags=["Metrics"])
async def get_detailed_metrics():
    metrics = store.get_metrics()
    return {
        "current":              metrics,
        "memory_history":       store.get_memory_history(),
        "cpu_history":          store.get_cpu_history(),
        "suspicious_over_time": store.get_suspicious_over_time(),
        "timestamp":            datetime.now().isoformat(),
    }


@app.get("/geo/connections", tags=["Threat Intelligence"])
async def get_geo_connections():
    metrics    = store.get_metrics()
    ext_ips: list[str] = [
        ip for ip in metrics.get("unique_ip_list", [])
        if not ip.startswith(("192.168.", "10.", "172.", "127.", "0.0.0.0", "255."))
    ]
    # Also extract external IPs from recent logs and alerts
    _private = ("192.168.", "10.", "172.", "127.", "0.0.0.0", "255.")
    for _log in store.get_logs(limit=300):
        for _k in ("src_ip", "dst_ip"):
            _ip = _log.get(_k, "")
            if _ip and _ip not in ext_ips and not _ip.startswith(_private):
                ext_ips.append(_ip)
    for _a in store.get_alerts(limit=100):
        for _k in ("src_ip", "dst_ip"):
            _ip = _a.get(_k, "")
            if _ip and _ip not in ext_ips and not _ip.startswith(_private):
                ext_ips.append(_ip)
    connections = get_geo_for_connections(ext_ips)
    # Fallback to threat intel DB
    if not connections:
        from threat_intel import THREAT_DATABASE, GEO_DATABASE
        connections = get_geo_for_connections(
            [ip for ip in THREAT_DATABASE if ip in GEO_DATABASE]
        )
    return {
        "vm_location":       VM_LOCATION,
        "connections":       connections,
        "total_external_ips": len(ext_ips),
        "mapped_ips":        len(connections),
        "timestamp":         datetime.now().isoformat(),
    }


@app.get("/threat-intel", tags=["Threat Intelligence"])
async def get_threat_intel_db():
    threats = get_all_known_threats()
    return {"threats": threats, "total_entries": len(threats), "timestamp": datetime.now().isoformat()}


@app.get("/threat-intel/{ip}", tags=["Threat Intelligence"])
async def get_threat_intel_ip(ip: str):
    result = lookup_ip(ip)
    return {"result": result, "timestamp": datetime.now().isoformat()}


@app.get("/threat-intel/hash/{sha256}", tags=["Threat Intelligence"])
async def get_threat_intel_hash(sha256: str):
    result = lookup_file_hash(sha256)
    if not result:
        return {"result": None, "message": "Not found or VirusTotal API key not configured"}
    return {"result": result, "timestamp": datetime.now().isoformat()}


# ============================================================
# Aggregated dashboard endpoint (single HTTP call)
# ============================================================

@app.get("/dashboard-data", tags=["Dashboard"])
async def get_dashboard_data():
    """Aggregated endpoint for Streamlit — returns all data in one HTTP request."""
    metrics = store.get_metrics()
    # 1) External IPs from in-memory metrics
    ext_ips: list[str] = [
        ip for ip in metrics.get("unique_ip_list", [])
        if not ip.startswith(("192.168.", "10.", "172.", "127.", "0.0.0.0", "255."))
    ]

    # 2) Also extract external IPs from recent log entries (SQLite)
    _private_prefixes = ("192.168.", "10.", "172.", "127.", "0.0.0.0", "255.")
    recent_logs = store.get_logs(limit=300)
    for _log in recent_logs:
        for _key in ("src_ip", "dst_ip"):
            _ip = _log.get(_key, "")
            if _ip and _ip not in ext_ips and not _ip.startswith(_private_prefixes):
                ext_ips.append(_ip)

    # 3) Also check alerts for external IPs
    recent_alerts = store.get_alerts(limit=100)
    for _alert in recent_alerts:
        for _key in ("src_ip", "dst_ip"):
            _ip = _alert.get(_key, "")
            if _ip and _ip not in ext_ips and not _ip.startswith(_private_prefixes):
                ext_ips.append(_ip)

    connections = get_geo_for_connections(ext_ips)

    # 4) Fallback: if no live external connections, show known threat
    #    intel IPs on the map so it is never empty
    if not connections:
        from threat_intel import THREAT_DATABASE, GEO_DATABASE
        fallback_ips = [ip for ip in THREAT_DATABASE if ip in GEO_DATABASE]
        connections = get_geo_for_connections(fallback_ips)

    return {
        "status":      metrics,
        "metrics":     {
            "current":              metrics,
            "memory_history":       store.get_memory_history(),
            "cpu_history":          store.get_cpu_history(),
            "suspicious_over_time": store.get_suspicious_over_time(),
        },
        "alerts":      {"alerts":   store.get_alerts(limit=50)},
        "timeline":    {"timeline": store.get_timeline(limit=50)},
        "events":      {"events":   store.get_logs(limit=80)},
        "geo":         {
            "vm_location": VM_LOCATION,
            "connections": connections,
        },
        "threat_intel": {"threats": get_all_known_threats()},
        "system_info":  _get_system_info(),
    }


# ============================================================
# Export endpoints
# ============================================================

@app.get("/export/logs", tags=["Export"])
async def export_logs():
    return JSONResponse(
        content=json.loads(store.export_logs_json()),
        headers={"Content-Disposition": "attachment; filename=vm_security_logs.json"},
    )


@app.get("/export/alerts", tags=["Export"])
async def export_alerts():
    return JSONResponse(
        content=json.loads(store.export_alerts_json()),
        headers={"Content-Disposition": "attachment; filename=vm_security_alerts.json"},
    )


@app.get("/report", tags=["Report"])
async def get_security_report():
    metrics        = store.get_metrics()
    alerts         = store.get_alerts(limit=200)
    critical_count = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    warning_count  = sum(1 for a in alerts if a.get("severity") == "WARNING")
    ext_ips        = [
        ip for ip in metrics.get("unique_ip_list", [])
        if not ip.startswith(("192.168.", "10.", "172.")) and ip not in config.TRUSTED_IPS
    ]
    sys_info = _get_system_info()
    return {
        "title":          "VM SECURITY REPORT",
        "generated_at":   datetime.now().isoformat(),
        "org":            config.ORG_NAME,
        "analyst":        config.ANALYST_NAME,
        "deployment_id":  config.DEPLOYMENT_ID,
        "system":         sys_info,
        "summary": {
            "suspicious_events": metrics.get("suspicious_events", 0),
            "unknown_ips":       len(ext_ips),
            "threat_score":      metrics.get("threat_score", 0),
            "memory_usage":      metrics.get("memory_usage", 0),
            "cpu_usage":         metrics.get("cpu_usage", 0),
            "status":            metrics.get("status", "SAFE"),
            "packets_per_sec":   metrics.get("packets_per_sec", 0),
        },
        "critical_alerts":       critical_count,
        "warning_alerts":        warning_count,
        "total_packets":         metrics.get("total_packets", 0),
        "unique_ips_total":      metrics.get("unique_ips", 0),
        "external_ips":          ext_ips,
        "protocol_distribution": metrics.get("protocol_counts", {}),
        "top_processes":         metrics.get("top_processes", []),
    }


# ============================================================
# Analyst notes
# ============================================================

class NoteRequest(BaseModel):
    note: str


@app.post("/analyst/note", tags=["Analyst"])
async def add_analyst_note(body: NoteRequest):
    store.add_analyst_note(body.note)
    return {"status": "saved", "timestamp": datetime.now().isoformat()}


@app.get("/analyst/notes", tags=["Analyst"])
async def get_analyst_notes(limit: int = Query(default=50, ge=1, le=200)):
    return {"notes": store.get_analyst_notes(limit=limit)}


# ============================================================
# Penetration Testing Scenarios (renamed from /simulate)
# ============================================================

def _run_in_background(fn):  # type: ignore[type-arg]
    threading.Thread(target=fn, daemon=True).start()


def _pentest_data_exfiltration() -> None:
    logger.warning("[PENTEST] Data Exfiltration scenario started")
    store.add_timeline_event("SYSTEM", "🔴 PENTEST: Data Exfiltration started", "WARNING")
    import os
    os.makedirs(config.SHARED_FOLDER_PATH, exist_ok=True)
    for fname in ["stolen_data.zip", "credentials_dump.txt", "database_export.csv"]:
        try:
            with open(os.path.join(config.SHARED_FOLDER_PATH, fname), "w") as f:
                f.write("PENTEST_DATA_" * random.randint(100, 500))
        except OSError:
            pass
        time.sleep(0.4)
    store.update_metrics({"memory_usage": 88.5, "cpu_usage": 72.3})
    store.add_memory_snapshot(88.5, 72.3)
    store.add_timeline_event("RESOURCE", "Memory spike to 88.5%", "CRITICAL")
    time.sleep(1)
    for i in range(12):
        dst = random.choice(["203.0.113.45", "198.51.100.23", "192.0.2.100"])
        store.add_log({
            "timestamp": datetime.now().isoformat(),
            "src_ip": config.VM_IP, "dst_ip": dst,
            "protocol": "TCP", "dst_port": 443,
            "packet_size": random.randint(1000, 1500),
        })
        store.increment_metric("total_packets")
        store.update_metrics({"unique_ips": dst, "protocol_counts": "TCP"})
        store.add_alert({
            "timestamp": datetime.now().isoformat(),
            "type": "NETWORK", "severity": "CRITICAL",
            "src_ip": config.VM_IP, "dst_ip": dst,
            "mitre": "T1041 — Exfiltration Over C2 Channel",
            "reasons": [f"External destination: {dst}", "Data exfiltration pattern"],
            "message": f"PENTEST: Data exfiltration to {dst} [T1041]",
        })
        store.increment_metric("suspicious_events")
        store.add_suspicious_event_timestamp()
        store.add_timeline_event("NETWORK", f"Exfil packet → {dst} [T1041]", "CRITICAL")
        time.sleep(0.3)
    store.update_metrics({"threat_score": 85, "status": "UNDER ATTACK"})
    store.add_timeline_event("BEHAVIORAL", "Data exfiltration attack confirmed [T1041]", "CRITICAL")
    store.persist_all()


def _pentest_malware_drop() -> None:
    logger.warning("[PENTEST] Malware Drop scenario started")
    store.add_timeline_event("SYSTEM", "🟡 PENTEST: Malware Drop started", "WARNING")
    import os
    malware_files = [
        ("trojan.exe", ".exe", "CRITICAL"),
        ("backdoor.dll", ".dll", "CRITICAL"),
        ("persistence.bat", ".bat", "CRITICAL"),
        ("payload.ps1", ".ps1", "CRITICAL"),
        ("dropper.scr", ".scr", "WARNING"),
    ]
    os.makedirs(config.SHARED_FOLDER_PATH, exist_ok=True)
    for fname, ext, severity in malware_files:
        fpath = os.path.join(config.SHARED_FOLDER_PATH, fname)
        try:
            with open(fpath, "w") as f:
                f.write("PENTEST_MALWARE_" * 50)
        except OSError:
            pass
        store.add_log({
            "timestamp": datetime.now().isoformat(),
            "type": "FILE", "event": "FILE_CREATED",
            "filename": fname, "filepath": fpath,
            "extension": ext,
            "file_size": random.randint(50000, 5000000),
            "suspicious": True, "severity": severity,
        })
        store.add_alert({
            "timestamp": datetime.now().isoformat(),
            "type": "FILE", "severity": severity,
            "filename": fname, "extension": ext,
            "mitre": "T1105 — Ingress Tool Transfer",
            "reasons": [f"Suspicious extension: {ext}", f"Malware file: {fname}"],
            "message": f"PENTEST: Malware dropped: {fname} ({ext}) [T1105]",
        })
        store.add_timeline_event("FILE", f"Malware dropped: {fname} [T1105]", severity)
        store.increment_metric("suspicious_events")
        store.add_suspicious_event_timestamp()
        time.sleep(0.8)
    store.update_metrics({"threat_score": 70, "status": "UNDER ATTACK"})
    store.persist_all()


def _pentest_beacon_c2() -> None:
    logger.warning("[PENTEST] C2 Beaconing scenario started")
    store.add_timeline_event("SYSTEM", "🔵 PENTEST: C2 Beaconing started", "WARNING")
    c2_server, c2_port = "198.51.100.42", 4444
    for i in range(15):
        store.add_log({
            "timestamp": datetime.now().isoformat(),
            "src_ip": config.VM_IP, "dst_ip": c2_server,
            "protocol": "TCP",
            "src_port": random.randint(1024, 65535),
            "dst_port": c2_port,
            "packet_size": random.randint(64, 256),
        })
        store.increment_metric("total_packets")
        store.update_metrics({"unique_ips": c2_server, "protocol_counts": "TCP"})
        if i >= 4:
            store.add_alert({
                "timestamp": datetime.now().isoformat(),
                "type": "NETWORK", "severity": "CRITICAL",
                "src_ip": config.VM_IP, "dst_ip": c2_server,
                "protocol": "TCP", "port": c2_port,
                "mitre": "T1071 — Application Layer Protocol",
                "reasons": [f"Beaconing to {c2_server}", f"Suspicious port: {c2_port}"],
                "message": f"PENTEST: C2 beacon → {c2_server}:{c2_port} [T1071]",
            })
            store.increment_metric("suspicious_events")
            store.add_suspicious_event_timestamp()
        store.add_timeline_event(
            "NETWORK",
            f"Beacon #{i+1}: {config.VM_IP} → {c2_server}:{c2_port} [T1071]",
            "CRITICAL" if i >= 4 else "WARNING",
        )
        time.sleep(random.uniform(1.5, 3.0))
    store.update_metrics({"threat_score": 90, "status": "UNDER ATTACK"})
    store.add_timeline_event("BEHAVIORAL", "C2 beaconing pattern confirmed [T1071]", "CRITICAL")
    store.persist_all()


def _pentest_full_attack() -> None:
    logger.warning("[PENTEST] Full Attack Chain started")
    store.add_timeline_event("SYSTEM", "⚫ PENTEST: FULL ATTACK CHAIN started", "CRITICAL")
    _pentest_malware_drop()
    time.sleep(2)
    _pentest_beacon_c2()
    time.sleep(2)
    _pentest_data_exfiltration()
    store.update_metrics({"threat_score": 95, "status": "UNDER ATTACK"})
    store.add_timeline_event("BEHAVIORAL", "FULL ATTACK CHAIN DETECTED — System compromised", "CRITICAL")
    store.persist_all()


_PENTEST_SCENARIOS = {
    "data_exfiltration": _pentest_data_exfiltration,
    "malware_drop":      _pentest_malware_drop,
    "beacon_c2":         _pentest_beacon_c2,
    "full_attack":       _pentest_full_attack,
}

# Keep backward-compatible /simulate/* route alias
@app.post("/simulate/{scenario}", tags=["Penetration Testing"])
@app.post("/pentest/{scenario}",  tags=["Penetration Testing"])
async def run_pentest(scenario: str, x_api_key: Optional[str] = Header(default=None)):
    """
    Trigger a penetration-testing scenario.
    Runs in a background thread — API responds immediately.
    """
    _check_auth(x_api_key)
    if scenario not in _PENTEST_SCENARIOS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario '{scenario}'. Available: {list(_PENTEST_SCENARIOS)}",
        )
    _run_in_background(_PENTEST_SCENARIOS[scenario])
    return {
        "status":    "started",
        "scenario":  scenario,
        "message":   f"Pen-test scenario '{scenario}' started in background",
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/system/reset", tags=["System"])
async def reset_system(x_api_key: Optional[str] = Header(default=None)):
    """Reset all in-memory metrics — use before each demo."""
    _check_auth(x_api_key)
    logger.info("System reset requested.")
    from data_store import Metrics
    with store._metrics_lock:
        store._metrics = Metrics()
        store.connection_tracker.clear()
        store.memory_history.clear()
        store.cpu_history.clear()
        store.suspicious_over_time.clear()
    store.add_timeline_event("SYSTEM", "System reset — metrics cleared", "INFO")
    return {"status": "reset_complete", "timestamp": datetime.now().isoformat()}


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host=config.API_HOST, port=config.API_PORT,
                reload=False, log_level="info")
