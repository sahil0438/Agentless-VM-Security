"""
Memory, CPU, Process, Disk & Network I/O Monitor — Industry-grade.
Uses psutil to provide real-time host metrics:
  - Memory and CPU usage (real, no simulation)
  - Top-N processes by CPU and Memory
  - Disk I/O rates (read/write bytes per second)
  - Network I/O rates (bytes sent/received per second)
"""

import logging
import threading
import time
from datetime import datetime
from typing import List, Optional

import psutil as _psutil  # type: ignore[import]

import config
from data_store import DataStore

logger = logging.getLogger("memory_monitor")

# Prime CPU counter so the first non-blocking call returns a valid value
_psutil.cpu_percent(interval=None)


class MemoryMonitor:
    """
    Monitors host memory, CPU, processes, disk I/O, and network I/O.
    All data is real — obtained directly from the OS via psutil.
    No simulation mode: psutil works on Windows, Linux, and macOS.
    """

    def __init__(self) -> None:
        self.store   = DataStore()
        self.running = False
        self._thread: Optional[threading.Thread] = None

        self._prev_memory      = 0.0
        self._prev_cpu         = 0.0
        self._high_memory_count = 0
        self._high_cpu_count    = 0

        # Disk I/O baseline
        self._prev_disk_read  = 0.0
        self._prev_disk_write = 0.0
        # Network I/O baseline
        self._prev_net_sent   = 0.0
        self._prev_net_recv   = 0.0
        self._prev_snapshot_time = time.monotonic()

        logger.info("MemoryMonitor initialised (real psutil, interval=%ds)",
                    config.RESOURCE_MONITOR_INTERVAL)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self.running:
            logger.warning("MemoryMonitor already running.")
            return
        self.running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("MemoryMonitor started.")
        self.store.add_timeline_event("SYSTEM", "Memory/CPU/Process/IO monitoring started", "INFO")

    def stop(self) -> None:
        self.running = False
        if self._thread is not None:
            self._thread.join(timeout=5)
        logger.info("MemoryMonitor stopped.")

    # ------------------------------------------------------------------
    # Main monitoring loop
    # ------------------------------------------------------------------

    def _monitor_loop(self) -> None:
        while self.running:
            try:
                self._collect_and_analyze()
                time.sleep(config.RESOURCE_MONITOR_INTERVAL)
            except Exception as exc:
                logger.error("MemoryMonitor error: %s", exc)
                time.sleep(config.RESOURCE_MONITOR_INTERVAL)

    def _collect_and_analyze(self) -> None:
        """Collect all system metrics and run anomaly detection."""
        now_mono = time.monotonic()
        elapsed  = max(0.1, now_mono - self._prev_snapshot_time)
        self._prev_snapshot_time = now_mono

        # ── Memory & CPU ──────────────────────────────────────
        mem_info   = _psutil.virtual_memory()
        memory_pct: float = mem_info.percent
        cpu_pct:    float = _psutil.cpu_percent(interval=None)

        # ── Disk I/O ──────────────────────────────────────────
        disk_io       = _psutil.disk_io_counters()
        disk_read_bps = 0.0
        disk_write_bps = 0.0
        if disk_io:
            disk_read_bps  = max(0.0, (disk_io.read_bytes  - self._prev_disk_read)  / elapsed)
            disk_write_bps = max(0.0, (disk_io.write_bytes - self._prev_disk_write) / elapsed)
            self._prev_disk_read  = float(disk_io.read_bytes)
            self._prev_disk_write = float(disk_io.write_bytes)

        # ── Network I/O ───────────────────────────────────────
        net_io = _psutil.net_io_counters()
        net_sent_bps = 0.0
        net_recv_bps = 0.0
        if net_io:
            net_sent_bps = max(0.0, (net_io.bytes_sent - self._prev_net_sent) / elapsed)
            net_recv_bps = max(0.0, (net_io.bytes_recv - self._prev_net_recv) / elapsed)
            self._prev_net_sent = float(net_io.bytes_sent)
            self._prev_net_recv = float(net_io.bytes_recv)

        # ── Top processes ─────────────────────────────────────
        top_procs = self._get_top_processes()

        # ── Push to store ─────────────────────────────────────
        self.store.update_metrics({
            "memory_usage":   memory_pct,
            "cpu_usage":      cpu_pct,
            "disk_read_bps":  disk_read_bps,
            "disk_write_bps": disk_write_bps,
            "net_bytes_sent": net_sent_bps,
            "net_bytes_recv": net_recv_bps,
            "top_processes":  top_procs,
        })
        self.store.add_memory_snapshot(memory_pct, cpu_pct)

        # ── Anomaly detection ─────────────────────────────────
        anomaly_delta = 0
        reasons: List[str] = []

        if memory_pct > config.MEMORY_CRITICAL_THRESHOLD:
            anomaly_delta += 15
            reasons.append(f"Critical memory: {memory_pct:.1f}%")
        elif memory_pct > config.MEMORY_WARNING_THRESHOLD:
            anomaly_delta += 8
            reasons.append(f"High memory: {memory_pct:.1f}%")
            self._high_memory_count += 1
        else:
            self._high_memory_count = max(0, self._high_memory_count - 1)

        if cpu_pct > config.CPU_CRITICAL_THRESHOLD:
            anomaly_delta += 10
            reasons.append(f"Critical CPU: {cpu_pct:.1f}%")
        elif cpu_pct > config.CPU_WARNING_THRESHOLD:
            anomaly_delta += 5
            reasons.append(f"High CPU: {cpu_pct:.1f}%")
            self._high_cpu_count += 1
        else:
            self._high_cpu_count = max(0, self._high_cpu_count - 1)

        # Sudden memory spike (>20% in one interval)
        memory_delta = memory_pct - self._prev_memory
        if memory_delta > 20:
            anomaly_delta += 25
            reasons.append(f"Memory spike: +{memory_delta:.1f}%")

        # Sustained high memory
        if self._high_memory_count >= 5:
            anomaly_delta += 10
            reasons.append(f"Sustained high memory ({self._high_memory_count} readings)")

        # Correlate: high CPU + suspicious network events
        metrics = self.store.get_metrics()
        if cpu_pct > config.CPU_WARNING_THRESHOLD and metrics.get("suspicious_events", 0) > 0:
            anomaly_delta += 25
            reasons.append(
                f"High CPU ({cpu_pct:.1f}%) correlated with "
                f"{metrics['suspicious_events']} suspicious network events"
            )

        # Correlate: high memory + external IP connections
        if memory_pct > config.MEMORY_WARNING_THRESHOLD:
            ext_ips = [
                ip for ip in metrics.get("unique_ip_list", [])
                if not ip.startswith(("192.168.", "10.", "172.")) and ip not in config.TRUSTED_IPS
            ]
            if ext_ips:
                anomaly_delta += 30
                reasons.append(f"High memory + external IPs: {', '.join(ext_ips[:3])}")

        # Large disk write spike (>50 MB/s could indicate data staging)
        if disk_write_bps > 50 * 1024 * 1024:
            anomaly_delta += 15
            reasons.append(f"High disk write: {disk_write_bps/1024/1024:.1f} MB/s")

        if anomaly_delta > 0:
            current_score = float(self.store.get_metrics().get("anomaly_score", 0))
            new_score = min(100.0, current_score + anomaly_delta)
            self.store.update_metrics({"anomaly_score": new_score})
            severity = "CRITICAL" if new_score >= config.THREAT_CRITICAL_THRESHOLD else "WARNING"
            self.store.add_alert({
                "timestamp":          datetime.now().isoformat(),
                "type":               "RESOURCE",
                "severity":           severity,
                "memory_usage":       memory_pct,
                "cpu_usage":          cpu_pct,
                "disk_write_mbps":    round(disk_write_bps / 1024 / 1024, 2),
                "anomaly_score_delta": anomaly_delta,
                "reasons":            reasons,
                "message":            " | ".join(reasons),
            })
            self.store.add_timeline_event("RESOURCE", reasons[0], severity)
            self.store.increment_metric("suspicious_events")
            self.store.add_suspicious_event_timestamp()
        else:
            # Decay anomaly score when system is healthy
            current_score = float(self.store.get_metrics().get("anomaly_score", 0))
            if current_score > 0:
                decay = config.ANOMALY_DECAY_RATE * (config.RESOURCE_MONITOR_INTERVAL / 60)
                self.store.update_metrics({"anomaly_score": max(0.0, current_score - decay)})

        self._prev_memory = memory_pct
        self._prev_cpu    = cpu_pct

        # Log snapshot
        self.store.add_log({
            "timestamp":          datetime.now().isoformat(),
            "type":               "RESOURCE",
            "memory_usage":       memory_pct,
            "cpu_usage":          cpu_pct,
            "memory_available_mb": mem_info.available / (1024 * 1024),
            "memory_total_mb":    mem_info.total / (1024 * 1024),
            "disk_read_mbps":     round(disk_read_bps  / 1024 / 1024, 3),
            "disk_write_mbps":    round(disk_write_bps / 1024 / 1024, 3),
            "net_sent_kbps":      round(net_sent_bps   / 1024, 2),
            "net_recv_kbps":      round(net_recv_bps   / 1024, 2),
        })

    # ------------------------------------------------------------------
    # Top process snapshot
    # ------------------------------------------------------------------

    def _get_top_processes(self) -> List[dict]:
        """Return the top-N processes ordered by CPU usage."""
        procs: List[dict] = []
        try:
            for proc in _psutil.process_iter(
                ["pid", "name", "cpu_percent", "memory_percent", "status"]
            ):
                try:
                    info = proc.info  # type: ignore[attr-defined]
                    procs.append({
                        "pid":     info["pid"],
                        "name":    info["name"] or "unknown",
                        "cpu":     round(info["cpu_percent"] or 0.0, 1),
                        "mem":     round(info["memory_percent"] or 0.0, 1),
                        "status":  info["status"] or "unknown",
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):  # type: ignore[attr-defined]
                    pass
            procs.sort(key=lambda p: p["cpu"], reverse=True)
            return procs[:config.TOP_PROCESS_COUNT]
        except Exception as exc:
            logger.debug("Process list error: %s", exc)
            return []


# ← keep psutil accessible in except clause above
import psutil  # noqa: E402  (re-import under plain name for exception class reference)
