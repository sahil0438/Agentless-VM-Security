"""
Data Store Module — Industry-grade, SQLite-backed centralized storage.
Replaces the fragile JSON-file approach with a proper relational database.
Supports fast queries, indexing, data retention, and thread-safe access.
"""

import copy
import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

import config

logger = logging.getLogger("data_store")


# ============================================================
# SQLite helper — each thread gets its own connection
# ============================================================

_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    """Return a thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(config.DB_FILE, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")   # write-ahead log for concurrency
        _local.conn.execute("PRAGMA synchronous=NORMAL") # safe + faster than FULL
    return _local.conn


def _init_db() -> None:
    """Create tables and indexes if they don't exist."""
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            type      TEXT    DEFAULT 'NETWORK',
            data      TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_logs_ts   ON logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_logs_type ON logs(type);

        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity  TEXT NOT NULL,
            type      TEXT NOT NULL,
            data      TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_type     ON alerts(type);

        CREATE TABLE IF NOT EXISTS timeline (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            time_display TEXT NOT NULL,
            type        TEXT NOT NULL,
            description TEXT NOT NULL,
            severity    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_timeline_ts  ON timeline(timestamp);

        CREATE TABLE IF NOT EXISTS threat_cache (
            ip         TEXT PRIMARY KEY,
            data       TEXT NOT NULL,
            cached_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS analyst_notes (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            note      TEXT NOT NULL
        );
    """)
    conn.commit()
    logger.info("SQLite database initialised at %s", config.DB_FILE)


# ============================================================
# Strongly-typed metrics container
# ============================================================

class Metrics:
    """Holds all real-time metrics with explicit types."""
    def __init__(self) -> None:
        self.total_packets:     int   = 0
        self.suspicious_events: int   = 0
        self.unique_ips:        Set[str] = set()
        self.threat_score:      int   = 0
        self.memory_usage:      float = 0.0
        self.cpu_usage:         float = 0.0
        self.disk_read_bps:     float = 0.0
        self.disk_write_bps:    float = 0.0
        self.net_bytes_sent:    float = 0.0
        self.net_bytes_recv:    float = 0.0
        self.packets_per_sec:   float = 0.0
        self.status:            str   = "SAFE"
        self.protocol_counts:   Dict[str, int] = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self.anomaly_score:     float = 0.0
        self.top_processes:     List[Dict] = []


# ============================================================
# DataStore — singleton, thread-safe
# ============================================================

class DataStore:
    """Thread-safe centralized data store backed by SQLite."""

    _instance: Optional["DataStore"] = None
    _lock:     threading.Lock = threading.Lock()

    def __new__(cls) -> "DataStore":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    inst = super().__new__(cls)
                    inst._initialized = False  # type: ignore[attr-defined]
                    cls._instance = inst
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        os.makedirs(config.DATA_DIR, exist_ok=True)
        _init_db()

        self._metrics_lock = threading.Lock()
        self._metrics       = Metrics()

        # In-memory helpers
        self.connection_tracker:    Dict[str, List[float]] = {}
        self.memory_history:        List[Dict] = []
        self.cpu_history:           List[Dict] = []
        self.suspicious_over_time:  List[Dict] = []

        # Packet-rate tracking
        self._pkt_timestamps:       List[float] = []
        self._pkt_ts_lock           = threading.Lock()

        logger.info("DataStore initialised (SQLite backend)")

    # ------------------------------------------------------------------
    # Log management
    # ------------------------------------------------------------------

    def add_log(self, entry: Dict) -> None:
        entry.setdefault("timestamp", datetime.now().isoformat())
        row_type = entry.get("type", "NETWORK")
        try:
            conn = _get_conn()
            conn.execute(
                "INSERT INTO logs (timestamp, type, data) VALUES (?, ?, ?)",
                (entry["timestamp"], row_type, json.dumps(entry, default=str))
            )
            conn.commit()
        except Exception as exc:
            logger.error("add_log error: %s", exc)

    def get_logs(self, limit: int = 100, log_type: Optional[str] = None,
                 since_hours: Optional[int] = None) -> List[Dict]:
        try:
            conn = _get_conn()
            query = "SELECT data FROM logs"
            params: list = []
            clauses: list = []
            if log_type:
                clauses.append("type = ?")
                params.append(log_type)
            if since_hours:
                cutoff = (datetime.now() - timedelta(hours=since_hours)).isoformat()
                clauses.append("timestamp >= ?")
                params.append(cutoff)
            if clauses:
                query += " WHERE " + " AND ".join(clauses)
            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(query, params).fetchall()
            return [json.loads(r["data"]) for r in reversed(rows)]
        except Exception as exc:
            logger.error("get_logs error: %s", exc)
            return []

    def export_logs_json(self) -> str:
        return json.dumps(self.get_logs(limit=10000), indent=2, default=str)

    # ------------------------------------------------------------------
    # Alert management
    # ------------------------------------------------------------------

    def add_alert(self, alert: Dict) -> None:
        alert.setdefault("timestamp", datetime.now().isoformat())
        try:
            conn = _get_conn()
            conn.execute(
                "INSERT INTO alerts (timestamp, severity, type, data) VALUES (?, ?, ?, ?)",
                (alert["timestamp"],
                 alert.get("severity", "INFO"),
                 alert.get("type", "SYSTEM"),
                 json.dumps(alert, default=str))
            )
            conn.commit()
        except Exception as exc:
            logger.error("add_alert error: %s", exc)

    def get_alerts(self, limit: int = 50, severity: Optional[str] = None,
                   since_hours: Optional[int] = None) -> List[Dict]:
        try:
            conn = _get_conn()
            query = "SELECT data FROM alerts"
            params: list = []
            clauses: list = []
            if severity:
                clauses.append("severity = ?")
                params.append(severity.upper())
            if since_hours:
                cutoff = (datetime.now() - timedelta(hours=since_hours)).isoformat()
                clauses.append("timestamp >= ?")
                params.append(cutoff)
            if clauses:
                query += " WHERE " + " AND ".join(clauses)
            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(query, params).fetchall()
            return [json.loads(r["data"]) for r in reversed(rows)]
        except Exception as exc:
            logger.error("get_alerts error: %s", exc)
            return []

    def export_alerts_json(self) -> str:
        return json.dumps(self.get_alerts(limit=10000), indent=2, default=str)

    # ------------------------------------------------------------------
    # Timeline management
    # ------------------------------------------------------------------

    def add_timeline_event(self, event_type: str, description: str,
                           severity: str = "INFO") -> None:
        now = datetime.now()
        try:
            conn = _get_conn()
            conn.execute(
                "INSERT INTO timeline (timestamp, time_display, type, description, severity)"
                " VALUES (?, ?, ?, ?, ?)",
                (now.isoformat(), now.strftime("%H:%M:%S"), event_type, description, severity)
            )
            conn.commit()
        except Exception as exc:
            logger.error("add_timeline_event error: %s", exc)

    def get_timeline(self, limit: int = 100) -> List[Dict]:
        try:
            conn = _get_conn()
            rows = conn.execute(
                "SELECT timestamp, time_display, type AS type, description, severity"
                " FROM timeline ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in reversed(rows)]
        except Exception as exc:
            logger.error("get_timeline error: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Metrics management
    # ------------------------------------------------------------------

    def update_metrics(self, updates: Dict) -> None:
        with self._metrics_lock:
            for key, value in updates.items():
                if key == "unique_ips" and isinstance(value, str):
                    self._metrics.unique_ips.add(value)
                elif key == "protocol_counts" and isinstance(value, str):
                    proto = value.upper()
                    if proto in self._metrics.protocol_counts:
                        self._metrics.protocol_counts[proto] += 1
                    else:
                        self._metrics.protocol_counts["OTHER"] += 1
                elif key == "total_packets"      and isinstance(value, int):
                    self._metrics.total_packets = value
                elif key == "suspicious_events"  and isinstance(value, int):
                    self._metrics.suspicious_events = value
                elif key == "threat_score"       and isinstance(value, (int, float)):
                    self._metrics.threat_score = int(value)
                elif key == "memory_usage"       and isinstance(value, (int, float)):
                    self._metrics.memory_usage = float(value)
                elif key == "cpu_usage"          and isinstance(value, (int, float)):
                    self._metrics.cpu_usage = float(value)
                elif key == "disk_read_bps"      and isinstance(value, (int, float)):
                    self._metrics.disk_read_bps = float(value)
                elif key == "disk_write_bps"     and isinstance(value, (int, float)):
                    self._metrics.disk_write_bps = float(value)
                elif key == "net_bytes_sent"     and isinstance(value, (int, float)):
                    self._metrics.net_bytes_sent = float(value)
                elif key == "net_bytes_recv"     and isinstance(value, (int, float)):
                    self._metrics.net_bytes_recv = float(value)
                elif key == "packets_per_sec"    and isinstance(value, (int, float)):
                    self._metrics.packets_per_sec = float(value)
                elif key == "status"             and isinstance(value, str):
                    self._metrics.status = value
                elif key == "anomaly_score"      and isinstance(value, (int, float)):
                    self._metrics.anomaly_score = float(value)
                elif key == "top_processes"      and isinstance(value, list):
                    self._metrics.top_processes = value

    def increment_metric(self, key: str, amount: int = 1) -> None:
        with self._metrics_lock:
            if key == "total_packets":
                self._metrics.total_packets += amount
            elif key == "suspicious_events":
                self._metrics.suspicious_events += amount

    def get_metrics(self) -> Dict:
        with self._metrics_lock:
            return {
                "total_packets":     self._metrics.total_packets,
                "suspicious_events": self._metrics.suspicious_events,
                "unique_ips":        len(self._metrics.unique_ips),
                "unique_ip_list":    list(self._metrics.unique_ips),
                "threat_score":      self._metrics.threat_score,
                "memory_usage":      self._metrics.memory_usage,
                "cpu_usage":         self._metrics.cpu_usage,
                "disk_read_bps":     self._metrics.disk_read_bps,
                "disk_write_bps":    self._metrics.disk_write_bps,
                "net_bytes_sent":    self._metrics.net_bytes_sent,
                "net_bytes_recv":    self._metrics.net_bytes_recv,
                "packets_per_sec":   self._metrics.packets_per_sec,
                "status":            self._metrics.status,
                "protocol_counts":   copy.copy(self._metrics.protocol_counts),
                "anomaly_score":     self._metrics.anomaly_score,
                "top_processes":     list(self._metrics.top_processes),
            }

    # ------------------------------------------------------------------
    # Packet-rate tracking
    # ------------------------------------------------------------------

    def record_packet_timestamp(self) -> None:
        """Record packet arrival time for packets/sec calculation."""
        import time
        now = time.monotonic()
        with self._pkt_ts_lock:
            self._pkt_timestamps.append(now)
            cutoff = now - 5.0   # sliding 5-second window
            self._pkt_timestamps = [t for t in self._pkt_timestamps if t > cutoff]
            pps = len(self._pkt_timestamps) / 5.0
        with self._metrics_lock:
            self._metrics.packets_per_sec = round(pps, 1)

    # ------------------------------------------------------------------
    # Connection / beaconing tracking
    # ------------------------------------------------------------------

    def track_connection(self, dst_ip: str, timestamp: float) -> bool:
        with self._metrics_lock:
            if dst_ip not in self.connection_tracker:
                self.connection_tracker[dst_ip] = []
            self.connection_tracker[dst_ip].append(timestamp)
            cutoff = timestamp - config.BEACON_TIME_WINDOW
            self.connection_tracker[dst_ip] = [
                t for t in self.connection_tracker[dst_ip] if t > cutoff
            ]
            return len(self.connection_tracker[dst_ip]) >= config.BEACON_THRESHOLD

    # ------------------------------------------------------------------
    # Resource history (in-memory ring buffers)
    # ------------------------------------------------------------------

    def add_memory_snapshot(self, memory_pct: float, cpu_pct: float) -> None:
        with self._metrics_lock:
            now = datetime.now().isoformat()
            self.memory_history.append({"timestamp": now, "memory_usage": memory_pct})
            self.cpu_history.append({"timestamp": now, "cpu_usage": cpu_pct})
            if len(self.memory_history) > 500:
                self.memory_history = self.memory_history[-500:]
            if len(self.cpu_history) > 500:
                self.cpu_history = self.cpu_history[-500:]

    def get_memory_history(self) -> List[Dict]:
        with self._metrics_lock:
            return list(self.memory_history)

    def get_cpu_history(self) -> List[Dict]:
        with self._metrics_lock:
            return list(self.cpu_history)

    # ------------------------------------------------------------------
    # Suspicious events over time
    # ------------------------------------------------------------------

    def add_suspicious_event_timestamp(self) -> None:
        with self._metrics_lock:
            now = datetime.now()
            minute_key = now.strftime("%H:%M")
            if (self.suspicious_over_time
                    and self.suspicious_over_time[-1]["time"] == minute_key):
                self.suspicious_over_time[-1]["count"] += 1
            else:
                self.suspicious_over_time.append({
                    "time":      minute_key,
                    "timestamp": now.isoformat(),
                    "count":     1,
                })
            if len(self.suspicious_over_time) > 60:
                self.suspicious_over_time = self.suspicious_over_time[-60:]

    def get_suspicious_over_time(self) -> List[Dict]:
        with self._metrics_lock:
            return list(self.suspicious_over_time)

    # ------------------------------------------------------------------
    # Threat intel cache
    # ------------------------------------------------------------------

    def cache_threat_intel(self, ip: str, data: Dict) -> None:
        try:
            conn = _get_conn()
            conn.execute(
                "INSERT OR REPLACE INTO threat_cache (ip, data, cached_at) VALUES (?, ?, ?)",
                (ip, json.dumps(data, default=str), datetime.now().isoformat())
            )
            conn.commit()
        except Exception as exc:
            logger.error("cache_threat_intel error: %s", exc)

    def get_cached_threat_intel(self, ip: str) -> Optional[Dict]:
        try:
            conn = _get_conn()
            row = conn.execute(
                "SELECT data, cached_at FROM threat_cache WHERE ip = ?", (ip,)
            ).fetchone()
            if row:
                cached_at = datetime.fromisoformat(row["cached_at"])
                if (datetime.now() - cached_at).total_seconds() < config.THREAT_INTEL_CACHE_TTL:
                    return json.loads(row["data"])
        except Exception as exc:
            logger.error("get_cached_threat_intel error: %s", exc)
        return None

    # ------------------------------------------------------------------
    # Analyst notes
    # ------------------------------------------------------------------

    def add_analyst_note(self, note: str) -> None:
        try:
            conn = _get_conn()
            conn.execute(
                "INSERT INTO analyst_notes (timestamp, note) VALUES (?, ?)",
                (datetime.now().isoformat(), note)
            )
            conn.commit()
        except Exception as exc:
            logger.error("add_analyst_note error: %s", exc)

    def get_analyst_notes(self, limit: int = 50) -> List[Dict]:
        try:
            conn = _get_conn()
            rows = conn.execute(
                "SELECT timestamp, note FROM analyst_notes ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception as exc:
            logger.error("get_analyst_notes error: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Data retention (run periodically)
    # ------------------------------------------------------------------

    def purge_old_data(self) -> None:
        """Delete records older than DATA_RETENTION_DAYS."""
        if config.DATA_RETENTION_DAYS <= 0:
            return
        cutoff = (datetime.now() - timedelta(days=config.DATA_RETENTION_DAYS)).isoformat()
        try:
            conn = _get_conn()
            for table in ("logs", "alerts", "timeline"):
                conn.execute(f"DELETE FROM {table} WHERE timestamp < ?", (cutoff,))  # noqa: S608
            conn.commit()
            logger.info("Purged records older than %d days", config.DATA_RETENTION_DAYS)
        except Exception as exc:
            logger.error("purge_old_data error: %s", exc)

    # ------------------------------------------------------------------
    # Legacy JSON persistence (kept for backward compat / export)
    # ------------------------------------------------------------------

    def persist_all(self) -> None:
        """Export current data to JSON files for backward compatibility."""
        try:
            with open(config.LOGS_FILE,    "w") as f:
                json.dump(self.get_logs(limit=10000),    f, indent=2, default=str)
            with open(config.ALERTS_FILE,  "w") as f:
                json.dump(self.get_alerts(limit=10000),  f, indent=2, default=str)
            tl = self.get_timeline(limit=500)
            with open(config.TIMELINE_FILE, "w") as f:
                json.dump(tl, f, indent=2, default=str)
        except Exception as exc:
            logger.error("persist_all error: %s", exc)
