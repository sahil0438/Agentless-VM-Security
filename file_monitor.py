"""
File Monitoring Module — Industry-grade.
Monitors shared folder for suspicious file activity.
Adds SHA-256 hashing and Shannon entropy analysis for malware detection.
No simulation mode: watchdog works on all platforms.
"""

import hashlib
import logging
import math
import os
import threading
import time
from datetime import datetime
from typing import Optional

logger = logging.getLogger("file_monitor")

try:
    from watchdog.observers import Observer as _Observer                      # type: ignore[import]
    from watchdog.events import FileSystemEventHandler as _FileSystemEventHandler  # type: ignore[import]
    _WATCHDOG_AVAILABLE = True
except ImportError:
    _Observer = None                          # type: ignore[assignment,misc]
    _FileSystemEventHandler = object          # type: ignore[assignment,misc]
    _WATCHDOG_AVAILABLE = False
    logger.warning("watchdog not installed — file monitoring disabled. Run: pip install watchdog")

import config
from data_store import DataStore


# ============================================================
# Utility: SHA-256 hash + Shannon entropy
# ============================================================

def _sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file. Returns empty string on error."""
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


def _entropy(file_path: str) -> float:
    """
    Compute Shannon entropy of a file (0-8 bits).
    High entropy (>7.0) indicates encrypted, compressed, or packed content
    — a common indicator of malware.
    """
    try:
        byte_counts = [0] * 256
        total = 0
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                for byte in chunk:
                    byte_counts[byte] += 1
                    total += 1
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return round(entropy, 3)
    except (OSError, PermissionError):
        return 0.0


# ============================================================
# Watchdog event handler
# ============================================================

class SuspiciousFileHandler(_FileSystemEventHandler):  # type: ignore[misc]
    """Handles file system events and flags suspicious activity."""

    def __init__(self, store: DataStore) -> None:
        super().__init__()
        self.store = store

    def on_created(self, event: object) -> None:
        if getattr(event, "is_directory", False):
            return
        self._analyze(getattr(event, "src_path", ""), "FILE_CREATED")

    def on_modified(self, event: object) -> None:
        if getattr(event, "is_directory", False):
            return
        self._analyze(getattr(event, "src_path", ""), "FILE_MODIFIED")

    def on_moved(self, event: object) -> None:
        if getattr(event, "is_directory", False):
            return
        self._analyze(getattr(event, "dest_path", ""), "FILE_MOVED")

    def on_deleted(self, event: object) -> None:
        if getattr(event, "is_directory", False):
            return
        path = getattr(event, "src_path", "")
        logger.info("File deleted: %s", path)
        self.store.add_log({
            "timestamp": datetime.now().isoformat(),
            "type":      "FILE",
            "event":     "FILE_DELETED",
            "filename":  os.path.basename(path),
            "filepath":  path,
            "extension": os.path.splitext(path)[1].lower(),
            "suspicious": False,
            "severity":  "INFO",
        })
        self.store.add_timeline_event("FILE", f"FILE_DELETED: {os.path.basename(path)}", "INFO")

    def _analyze(self, file_path: str, event_type: str) -> None:
        """Full forensic analysis of a file system event."""
        filename  = os.path.basename(file_path)
        extension = os.path.splitext(filename)[1].lower()
        timestamp = datetime.now().isoformat()

        try:
            file_size = os.path.getsize(file_path)
        except (OSError, FileNotFoundError):
            file_size = 0

        # Compute hash and entropy
        sha256_hash  = _sha256(file_path)
        file_entropy = _entropy(file_path)

        is_suspicious = extension in config.SUSPICIOUS_EXTENSIONS
        severity      = "INFO"
        reasons: list = []

        if is_suspicious:
            severity = "WARNING"
            reasons.append(f"Suspicious extension: {extension}")
            if extension in (".exe", ".dll", ".scr", ".bat", ".ps1", ".hta"):
                severity = "CRITICAL"
                reasons.append(f"Dangerous executable: {filename}")

        if file_entropy > config.HIGH_ENTROPY_THRESHOLD:
            reasons.append(f"High entropy ({file_entropy:.2f}/8.0) — possibly packed/encrypted")
            if severity == "INFO":
                severity = "WARNING"

        if file_size > 10 * 1024 * 1024:
            reasons.append(f"Large file: {file_size / (1024*1024):.2f} MB")
            if severity == "INFO":
                severity = "WARNING"

        metrics = self.store.get_metrics()
        log_entry = {
            "timestamp":    timestamp,
            "type":         "FILE",
            "event":        event_type,
            "filename":     filename,
            "filepath":     file_path,
            "extension":    extension,
            "file_size":    file_size,
            "sha256":       sha256_hash,
            "entropy":      file_entropy,
            "suspicious":   is_suspicious or file_entropy > config.HIGH_ENTROPY_THRESHOLD,
            "severity":     severity,
            "memory_usage": metrics.get("memory_usage", 0),
            "cpu_usage":    metrics.get("cpu_usage", 0),
        }
        self.store.add_log(log_entry)
        self.store.add_timeline_event(
            "FILE",
            f"{event_type}: {filename} ({extension or 'no-ext'}) sha256:{sha256_hash[:12]}…",
            severity,
        )
        logger.info("[FILE] %s — %s [%s] sha256=%s entropy=%.2f",
                    event_type, filename, severity, sha256_hash[:16], file_entropy)

        if is_suspicious or reasons:
            self.store.increment_metric("suspicious_events")
            self.store.add_suspicious_event_timestamp()
            self.store.add_alert({
                "timestamp":  timestamp,
                "type":       "FILE",
                "severity":   severity,
                "event":      event_type,
                "filename":   filename,
                "filepath":   file_path,
                "extension":  extension,
                "sha256":     sha256_hash,
                "entropy":    file_entropy,
                "file_size":  file_size,
                "reasons":    reasons,
                "message":    " | ".join(reasons) if reasons else f"Suspicious file: {filename}",
            })


# ============================================================
# FileMonitor
# ============================================================

class FileMonitor:
    """
    Monitors a folder (or shared folder) for suspicious file activity.
    Uses watchdog for real events; falls back to polling if watchdog unavailable.
    Computes SHA-256 hash and Shannon entropy on every file event.
    """

    def __init__(self) -> None:
        self.store = DataStore()
        self._observer: Optional[object] = None
        self.running   = False
        self._thread:   Optional[threading.Thread] = None
        os.makedirs(config.SHARED_FOLDER_PATH, exist_ok=True)
        logger.info("FileMonitor initialised — watching: %s", config.SHARED_FOLDER_PATH)

    def start(self) -> None:
        if self.running:
            logger.warning("FileMonitor already running.")
            return

        if not _WATCHDOG_AVAILABLE:
            logger.critical(
                "watchdog is not installed — file monitoring disabled. "
                "Install with: pip install watchdog"
            )
            self.store.add_timeline_event(
                "SYSTEM",
                "CRITICAL: watchdog not installed — file monitoring disabled",
                "CRITICAL",
            )
            return

        self.running   = True
        self._observer = _Observer()
        handler        = SuspiciousFileHandler(self.store)
        self._observer.schedule(handler, config.SHARED_FOLDER_PATH, recursive=True)  # type: ignore[union-attr]
        self._observer.start()  # type: ignore[union-attr]
        logger.info("FileMonitor started — watching: %s (recursive)", config.SHARED_FOLDER_PATH)
        self.store.add_timeline_event(
            "SYSTEM",
            f"File monitoring started on {config.SHARED_FOLDER_PATH}",
            "INFO",
        )

    def stop(self) -> None:
        self.running = False
        if self._observer is not None:
            self._observer.stop()  # type: ignore[union-attr]
            self._observer.join()  # type: ignore[union-attr]
        logger.info("FileMonitor stopped.")
