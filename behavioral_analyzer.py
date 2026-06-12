"""
Behavioral Analyzer Engine — Rule-based threat detection system.
Industry-grade correlation engine.
Correlates signals from network, file, and memory monitors
to generate threat scores, alert messages, and MITRE ATT&CK mappings.
"""

import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import config
from data_store import DataStore

logger = logging.getLogger("behavioral_analyzer")

class BehavioralAnalyzer:
    """
    Rule-based behavioural analysis engine.
    Combines signals from all monitoring modules to calculate
    threat scores and detect complex attack patterns.
    """

    def __init__(self) -> None:
        self.store = DataStore()
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._analysis_interval = 2  # Frequent fast analysis

        self._last_analysis_time = datetime.now()
        self._alert_cooldown: Dict[str, datetime] = {}
        self._cooldown_duration = timedelta(seconds=20)

        logger.info("BehavioralAnalyzer initialised with rule-based detection engine.")

    def start(self) -> None:
        """Start the behavioural analysis thread."""
        if self.running:
            logger.warning("BehavioralAnalyzer already running.")
            return
        self.running = True
        self._thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self._thread.start()
        logger.info("Started behavioural analysis engine.")
        self.store.add_timeline_event("SYSTEM", "Behavioral analyzer engine started", "INFO")

    def stop(self) -> None:
        """Stop the behavioural analysis thread."""
        self.running = False
        if self._thread is not None:
            self._thread.join(timeout=5)
        logger.info("BehavioralAnalyzer stopped.")

    def _analysis_loop(self) -> None:
        """Main analysis loop - periodically evaluates all signals."""
        while self.running:
            try:
                self._run_analysis()
                time.sleep(self._analysis_interval)
            except Exception as e:
                logger.error("BehavioralAnalyzer Error: %s", e)
                time.sleep(self._analysis_interval)

    def _run_analysis(self) -> None:
        """Execute all behavioural analysis rules."""
        metrics = self.store.get_metrics()
        recent_logs = self.store.get_logs(limit=80)
        recent_alerts = self.store.get_alerts(limit=30)

        threat_score, _ = self._calculate_threat_score(metrics, recent_logs, recent_alerts)
        self.store.update_metrics({"threat_score": threat_score})

        if threat_score >= config.THREAT_CRITICAL_THRESHOLD:
            status = "UNDER ATTACK"
        elif threat_score >= config.THREAT_WARNING_THRESHOLD:
            status = "WARNING"
        else:
            status = "SAFE"
        self.store.update_metrics({"status": status})

        self._check_composite_rules(metrics, recent_logs, recent_alerts)
        self._infer_process_behavior(metrics, recent_logs)
        self._last_analysis_time = datetime.now()

    def _calculate_threat_score(
        self, metrics: Dict, logs: List[Dict], alerts: List[Dict]
    ) -> Tuple[int, List[str]]:
        """
        Calculate a composite threat score (0-100) based on all available signals.
        Returns (score, reasons).
        """
        score = 0
        reasons: List[str] = []

        suspicious_events: int = int(metrics.get("suspicious_events", 0))
        if suspicious_events > 0:
            network_score = min(30, suspicious_events * 3)
            score += network_score
            reasons.append(f"Network suspicious events: {suspicious_events} (+{network_score})")

        unique_ip_list: List[str] = list(metrics.get("unique_ip_list", []))
        external_ips = [
            ip for ip in unique_ip_list
            if not ip.startswith(("192.168.", "10.", "172.", "127."))
            and ip not in config.TRUSTED_IPS
        ]
        if external_ips:
            ext_score = min(20, len(external_ips) * 5)
            score += ext_score
            reasons.append(f"External IP connections: {len(external_ips)} (+{ext_score})")

        memory_usage: float = float(metrics.get("memory_usage", 0))
        cpu_usage: float = float(metrics.get("cpu_usage", 0))

        if memory_usage > config.MEMORY_CRITICAL_THRESHOLD:
            score += 15
            reasons.append(f"Critical memory: {memory_usage:.1f}% (+15)")
        elif memory_usage > config.MEMORY_WARNING_THRESHOLD:
            score += 8
            reasons.append(f"High memory: {memory_usage:.1f}% (+8)")

        if cpu_usage > config.CPU_CRITICAL_THRESHOLD:
            score += 10
            reasons.append(f"Critical CPU: {cpu_usage:.1f}% (+10)")
        elif cpu_usage > config.CPU_WARNING_THRESHOLD:
            score += 5
            reasons.append(f"High CPU: {cpu_usage:.1f}% (+5)")

        recent_file_alerts = [
            a for a in alerts
            if a.get("type") == "FILE" and a.get("severity") in ["WARNING", "CRITICAL"]
        ]
        if recent_file_alerts:
            file_score = min(25, len(recent_file_alerts) * 8)
            score += file_score
            reasons.append(f"Suspicious file events: {len(recent_file_alerts)} (+{file_score})")

        anomaly_score: float = float(metrics.get("anomaly_score", 0))
        if anomaly_score > 0:
            score += min(20, int(anomaly_score * 0.2))

        return min(100, score), reasons

    def _check_composite_rules(
        self, metrics: Dict, logs: List[Dict], alerts: List[Dict]
    ) -> None:
        """Check composite rules that combine multiple signal sources."""
        now = datetime.now()
        memory_usage: float = float(metrics.get("memory_usage", 0))
        cpu_usage: float = float(metrics.get("cpu_usage", 0))
        suspicious_events: int = int(metrics.get("suspicious_events", 0))

        recent_network_alerts = [a for a in alerts if a.get("type") == "NETWORK"]
        recent_file_alerts = [a for a in alerts if a.get("type") == "FILE"]
        recent_resource_alerts = [a for a in alerts if a.get("type") == "RESOURCE"]

        has_network_activity = len(recent_network_alerts) > 0
        has_file_activity = len(recent_file_alerts) > 0
        has_resource_anomaly = len(recent_resource_alerts) > 0

        if has_network_activity and has_file_activity:
            rule_id = "NETWORK_FILE_CORRELATION"
            if self._can_alert(rule_id, now):
                self._create_composite_alert(
                    rule_id=rule_id,
                    mitre="T1105 — Ingress Tool Transfer (Correlation)",
                    severity="CRITICAL",
                    score_delta=40,
                    message="CRITICAL: Network activity correlated with file system changes [T1105]",
                    details={
                        "network_alerts": len(recent_network_alerts),
                        "file_alerts": len(recent_file_alerts),
                    },
                )

        if memory_usage > config.MEMORY_WARNING_THRESHOLD and has_network_activity:
            rule_id = "MEMORY_NETWORK_CORRELATION"
            if self._can_alert(rule_id, now):
                self._create_composite_alert(
                    rule_id=rule_id,
                    mitre="T1041 — Exfiltration Over C2 Channel",
                    severity="CRITICAL",
                    score_delta=30,
                    message=f"High memory ({memory_usage:.1f}%) with concurrent network activity [T1041]",
                    details={
                        "memory_usage": memory_usage,
                        "network_events": len(recent_network_alerts),
                    },
                )

        if cpu_usage > config.CPU_WARNING_THRESHOLD and suspicious_events > 3:
            rule_id = "CPU_BEACON_CORRELATION"
            if self._can_alert(rule_id, now):
                self._create_composite_alert(
                    rule_id=rule_id,
                    mitre="T1496 — Resource Hijacking",
                    severity="WARNING",
                    score_delta=25,
                    message=f"High CPU ({cpu_usage:.1f}%) with repeated suspicious packets ({suspicious_events}) [T1496]",
                    details={
                        "cpu_usage": cpu_usage,
                        "suspicious_events": suspicious_events,
                    },
                )

        if has_network_activity and has_file_activity and has_resource_anomaly:
            rule_id = "MULTI_VECTOR_ATTACK"
            if self._can_alert(rule_id, now):
                self._create_composite_alert(
                    rule_id=rule_id,
                    mitre="T1486 — Data Encrypted for Impact",
                    severity="CRITICAL",
                    score_delta=50,
                    message="MULTI-VECTOR THREAT: Network + File + Resource anomalies detected simultaneously [T1486]",
                    details={
                        "network_alerts": len(recent_network_alerts),
                        "file_alerts": len(recent_file_alerts),
                        "resource_alerts": len(recent_resource_alerts),
                        "memory_usage": memory_usage,
                        "cpu_usage": cpu_usage,
                    },
                )

    def _infer_process_behavior(self, metrics: Dict, logs: List[Dict]) -> None:
        """
        Process Behaviour Inference Module.
        Since the system is agentless, infer process behaviour from indirect signals.
        """
        now = datetime.now()
        memory_usage: float = float(metrics.get("memory_usage", 0))
        cpu_usage: float = float(metrics.get("cpu_usage", 0))

        recent_network_logs = sum(
            1 for lg in logs if lg.get("protocol") in ["TCP", "UDP", "ICMP"]
        )
        recent_file_logs = sum(1 for lg in logs if lg.get("type") == "FILE")

        if (
            recent_network_logs > 10
            and recent_file_logs > 0
            and memory_usage > config.MEMORY_WARNING_THRESHOLD
        ):
            rule_id = "INFER_DATA_EXFILTRATION"
            if self._can_alert(rule_id, now):
                self.store.add_timeline_event(
                    "PROCESS_INFERENCE",
                    f"Possible data exfiltration [T1041]: high network ({recent_network_logs} pkts) + file activity + high memory ({memory_usage:.1f}%)",
                    "CRITICAL",
                )
                self._alert_cooldown[rule_id] = now

        if cpu_usage > config.CPU_WARNING_THRESHOLD and recent_network_logs > 15:
            rule_id = "INFER_CRYPTO_C2"
            if self._can_alert(rule_id, now):
                self.store.add_timeline_event(
                    "PROCESS_INFERENCE",
                    f"Possible crypto mining or C2 [T1496]: high CPU ({cpu_usage:.1f}%) + high network traffic ({recent_network_logs} pkts)",
                    "WARNING",
                )
                self._alert_cooldown[rule_id] = now

        suspicious_files = sum(
            1 for lg in logs
            if lg.get("type") == "FILE" and lg.get("suspicious", False)
        )
        if suspicious_files > 0:
            rule_id = "INFER_MALWARE_DROP"
            if self._can_alert(rule_id, now):
                self.store.add_timeline_event(
                    "PROCESS_INFERENCE",
                    f"Possible malware drop [T1105]: {suspicious_files} suspicious files detected in shared folder",
                    "CRITICAL",
                )
                self._alert_cooldown[rule_id] = now

    def _can_alert(self, rule_id: str, now: datetime) -> bool:
        """Check if enough time has passed since last alert for this rule."""
        last_alert = self._alert_cooldown.get(rule_id)
        if last_alert is None or (now - last_alert) > self._cooldown_duration:
            return True
        return False

    def _create_composite_alert(
        self,
        rule_id: str,
        mitre: str,
        severity: str,
        score_delta: int,
        message: str,
        details: Dict,
    ) -> None:
        """Create a composite alert from correlated events."""
        now = datetime.now()
        self._alert_cooldown[rule_id] = now

        alert = {
            "timestamp": now.isoformat(),
            "type": "BEHAVIORAL",
            "rule_id": rule_id,
            "mitre": mitre,
            "severity": severity,
            "score_delta": score_delta,
            "message": message,
            "details": details,
            "reasons": [message],
        }
        self.store.add_alert(alert)
        self.store.add_timeline_event("BEHAVIORAL", message, severity)
        self.store.increment_metric("suspicious_events")
        self.store.add_suspicious_event_timestamp()

        current_score = float(self.store.get_metrics().get("anomaly_score", 0))
        new_score = min(100.0, current_score + score_delta)
        self.store.update_metrics({"anomaly_score": new_score})

        logger.info("[%s] Composite Alert: %s", severity, message)
