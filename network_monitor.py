"""
Network Monitoring Module — Industry-grade agentless network traffic analysis.
Captures ALL packets on the active interface (promiscuous mode, like Wireshark).
Performs real-time threat detection: unknown IPs, suspicious ports, beaconing.
Falls back to a minimal safe simulation ONLY when admin privileges are missing.
"""

import logging
import threading
import time
from datetime import datetime
from typing import Optional

logger = logging.getLogger("network_monitor")

try:
    from scapy.all import IP, TCP, UDP, ICMP, conf as scapy_conf  # type: ignore[import]
    from scapy.all import sniff as scapy_sniff                      # type: ignore[import]
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False
    logger.warning("Scapy not installed — network sniffing disabled. Install with: pip install scapy")

import config
from data_store import DataStore


class NetworkMonitor:
    """
    Monitors ALL network traffic on the host's active interface.
    Captures in promiscuous mode to match Wireshark packet counts.
    Performs real-time detection of suspicious IPs, ports, and beaconing.
    """

    def __init__(self) -> None:
        self.store   = DataStore()
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._packet_count = 0
        self._packet_lock  = threading.Lock()

        logger.info("NetworkMonitor initialised — Interface: %s | Promiscuous: %s",
                    config.NETWORK_INTERFACE, config.PROMISCUOUS_CAPTURE)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self.running:
            logger.warning("NetworkMonitor already running.")
            return
        self.running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        logger.info("NetworkMonitor started — capturing on %s", config.NETWORK_INTERFACE)
        self.store.add_timeline_event("SYSTEM", f"Network monitoring started on {config.NETWORK_INTERFACE}", "INFO")

    def stop(self) -> None:
        self.running = False
        if self._thread is not None:
            self._thread.join(timeout=5)
        with self._packet_lock:
            count = self._packet_count
        logger.info("NetworkMonitor stopped. Total packets captured: %d", count)

    # ------------------------------------------------------------------
    # Sniff loop
    # ------------------------------------------------------------------

    def _sniff_loop(self) -> None:
        if not _SCAPY_AVAILABLE:
            logger.critical(
                "Scapy is not installed. Real packet capture is DISABLED. "
                "Run: pip install scapy  then restart as Administrator."
            )
            self.store.add_timeline_event(
                "SYSTEM",
                "CRITICAL: Scapy not installed — packet capture disabled",
                "CRITICAL",
            )
            self._safe_simulation_mode()
            return

        # Try real capture first
        try:
            logger.info("Starting packet capture on interface: %s (promiscuous=%s)",
                        config.NETWORK_INTERFACE, config.PROMISCUOUS_CAPTURE)

            # Build BPF filter: capture ALL IP traffic (no VM_IP restriction)
            bpf_filter = "ip" if config.PROMISCUOUS_CAPTURE else f"host {config.VM_IP}"

            scapy_sniff(
                iface=config.NETWORK_INTERFACE,
                prn=self._process_packet,
                store=False,
                filter=bpf_filter,
                stop_filter=lambda _: not self.running,
            )

        except PermissionError:
            logger.critical(
                "PERMISSION DENIED — Run as Administrator/root for real packet capture. "
                "Falling back to safe simulation mode."
            )
            self.store.add_timeline_event(
                "SYSTEM",
                "PERMISSION DENIED: Admin privileges required for real packet capture",
                "CRITICAL",
            )
            self._safe_simulation_mode()

        except Exception as exc:
            logger.error("Packet capture error on interface '%s': %s — trying simulation.",
                         config.NETWORK_INTERFACE, exc)
            self.store.add_timeline_event(
                "SYSTEM",
                f"Network capture error ({config.NETWORK_INTERFACE}): {exc}",
                "WARNING",
            )
            self._safe_simulation_mode()

    # ------------------------------------------------------------------
    # Per-packet processing
    # ------------------------------------------------------------------

    def _process_packet(self, packet: object) -> None:
        """Process a captured packet — extract fields and run threat detection."""
        if not _SCAPY_AVAILABLE:
            return
        if not packet.haslayer(IP):  # type: ignore[union-attr]
            return

        ip_layer = packet[IP]       # type: ignore[index]
        src_ip: str = ip_layer.src
        dst_ip: str = ip_layer.dst
        protocol  = "OTHER"
        src_port  = 0
        dst_port  = 0
        packet_size = len(packet)   # type: ignore[arg-type]

        if packet.haslayer(TCP):    # type: ignore[union-attr]
            protocol = "TCP"
            src_port = packet[TCP].sport  # type: ignore[index]
            dst_port = packet[TCP].dport  # type: ignore[index]
        elif packet.haslayer(UDP):  # type: ignore[union-attr]
            protocol = "UDP"
            src_port = packet[UDP].sport  # type: ignore[index]
            dst_port = packet[UDP].dport  # type: ignore[index]
        elif packet.haslayer(ICMP): # type: ignore[union-attr]
            protocol = "ICMP"

        with self._packet_lock:
            self._packet_count += 1

        # Update store
        self.store.record_packet_timestamp()
        current_metrics = self.store.get_metrics()
        log_entry = {
            "timestamp":    datetime.now().isoformat(),
            "src_ip":       src_ip,
            "dst_ip":       dst_ip,
            "protocol":     protocol,
            "src_port":     src_port,
            "dst_port":     dst_port,
            "packet_size":  packet_size,
            "memory_usage": current_metrics.get("memory_usage", 0),
            "cpu_usage":    current_metrics.get("cpu_usage", 0),
        }
        self.store.add_log(log_entry)
        self.store.increment_metric("total_packets")
        self.store.update_metrics({"unique_ips": src_ip})
        self.store.update_metrics({"unique_ips": dst_ip})
        self.store.update_metrics({"protocol_counts": protocol})

        self._run_threat_detection(src_ip, dst_ip, src_port, dst_port, protocol)

    # ------------------------------------------------------------------
    # Threat detection (shared by real + simulation paths)
    # ------------------------------------------------------------------

    def _run_threat_detection(
        self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str
    ) -> None:
        """Rule-based threat detection on individual packets."""
        suspicious    = False
        threat_reasons: list = []

        is_src_external = (
            src_ip not in config.TRUSTED_IPS
            and not any(src_ip.startswith(p) for p in ("192.168.", "10.", "172.", "127."))
        )
        is_dst_external = (
            dst_ip not in config.TRUSTED_IPS
            and not any(dst_ip.startswith(p) for p in ("192.168.", "10.", "172.", "127."))
        )

        if is_src_external:
            suspicious = True
            threat_reasons.append(f"Unknown external source: {src_ip}")
        if is_dst_external:
            suspicious = True
            threat_reasons.append(f"Unknown external destination: {dst_ip}")
        if dst_port in config.SUSPICIOUS_PORTS:
            suspicious = True
            threat_reasons.append(f"Suspicious dest port: {dst_port}")
        if src_port in config.SUSPICIOUS_PORTS:
            suspicious = True
            threat_reasons.append(f"Suspicious src port: {src_port}")

        target_ip = dst_ip if src_ip == config.VM_IP else src_ip
        if self.store.track_connection(target_ip, time.time()):
            suspicious = True
            threat_reasons.append(
                f"Beaconing to {target_ip} "
                f"(≥{config.BEACON_THRESHOLD} connections in {config.BEACON_TIME_WINDOW}s)"
            )

        if suspicious:
            self.store.increment_metric("suspicious_events")
            self.store.add_suspicious_event_timestamp()
            severity = "CRITICAL" if len(threat_reasons) >= 2 else "WARNING"
            alert = {
                "timestamp": datetime.now().isoformat(),
                "type":      "NETWORK",
                "severity":  severity,
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "protocol":  protocol,
                "port":      dst_port,
                "reasons":   threat_reasons,
                "message":   " | ".join(threat_reasons),
            }
            self.store.add_alert(alert)
            self.store.add_timeline_event(
                "NETWORK",
                f"Suspicious: {src_ip} → {dst_ip} ({protocol}) — " + threat_reasons[0],
                severity,
            )

    # ------------------------------------------------------------------
    # Safe simulation mode (NO fake attacks — only benign local traffic)
    # ------------------------------------------------------------------

    def _safe_simulation_mode(self) -> None:
        """
        Generates benign background traffic for testing when real capture
        is unavailable. Does NOT generate suspicious IPs or ports — the
        system will stay SAFE until a pen-test scenario is manually triggered.
        """
        import random

        logger.info("NetworkMonitor: running benign simulation mode (no synthetic attacks)")

        benign_ips    = ["192.168.1.1", "192.168.1.50", "10.0.0.1", "10.0.0.5"]
        protocols     = ["TCP", "UDP", "ICMP"]
        benign_ports  = [80, 443, 53, 22, 3306, 5432]

        while self.running:
            try:
                src_ip      = config.VM_IP
                dst_ip      = random.choice(benign_ips)
                protocol    = random.choices(protocols, weights=[60, 30, 10])[0]
                dst_port    = random.choice(benign_ports)
                src_port    = random.randint(1024, 65535)
                packet_size = random.randint(40, 1200)

                with self._packet_lock:
                    self._packet_count += 1

                self.store.record_packet_timestamp()
                metrics = self.store.get_metrics()
                self.store.add_log({
                    "timestamp":    datetime.now().isoformat(),
                    "src_ip":       src_ip,
                    "dst_ip":       dst_ip,
                    "protocol":     protocol,
                    "src_port":     src_port,
                    "dst_port":     dst_port,
                    "packet_size":  packet_size,
                    "memory_usage": metrics.get("memory_usage", 0),
                    "cpu_usage":    metrics.get("cpu_usage", 0),
                })
                self.store.increment_metric("total_packets")
                self.store.update_metrics({"unique_ips": src_ip})
                self.store.update_metrics({"unique_ips": dst_ip})
                self.store.update_metrics({"protocol_counts": protocol})

                time.sleep(random.uniform(0.3, 1.5))

            except Exception as exc:
                logger.error("Simulation error: %s", exc)
                time.sleep(1)
