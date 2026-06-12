"""
Attack Simulation Script - Simulates various attack scenarios.
Generates synthetic malicious activities to test the monitoring system.

Usage:
    python simulate_attack.py [scenario]

Scenarios:
    1. data_exfiltration - Simulates data theft
    2. malware_drop      - Simulates malware file drops
    3. beacon_c2         - Simulates C2 beaconing
    4. full_attack       - Runs all scenarios in sequence
"""

import os
import sys
import time
import random
import json
from datetime import datetime

# Add project directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from data_store import DataStore


def banner():
    """Print simulation banner."""
    print("""
╔══════════════════════════════════════════════════════╗
║        ATTACK SIMULATION TOOL                        ║
║        VM Introspection Security System              ║
║                                                      ║
║   WARNING: This is for TESTING purposes only.        ║
║   Do NOT use on production systems.                  ║
╚══════════════════════════════════════════════════════╝
    """)


def simulate_data_exfiltration(store):
    """
    Scenario 1: Data Exfiltration
    - High network traffic to external IPs
    - Large file creation
    - High memory usage
    """
    print("\n[*] Starting Scenario: DATA EXFILTRATION")
    print("[*] Simulating data collection and exfiltration...\n")

    # Phase 1: Data collection (file creation)
    print("[1/4] Creating suspicious files in shared folder...")
    suspicious_files = [
        "stolen_data.zip",
        "credentials_dump.txt",
        "database_export.csv",
        "keylog_output.dat",
    ]
    os.makedirs(config.SHARED_FOLDER_PATH, exist_ok=True)
    for fname in suspicious_files:
        fpath = os.path.join(config.SHARED_FOLDER_PATH, fname)
        with open(fpath, "w") as f:
            f.write("SIMULATED_DATA_" * random.randint(100, 1000))
        print(f"    [+] Created: {fname}")
        time.sleep(1)

    # Phase 2: High memory simulation
    print("\n[2/4] Simulating high memory usage...")
    store.update_metrics({"memory_usage": 88.5, "cpu_usage": 72.3})
    store.add_memory_snapshot(88.5, 72.3)
    store.add_timeline_event("RESOURCE", "Memory spike to 88.5%", "CRITICAL")
    time.sleep(2)

    # Phase 3: Network exfiltration simulation
    print("[3/4] Simulating network exfiltration...")
    external_ips = ["203.0.113.45", "198.51.100.23", "192.0.2.100"]
    for i in range(15):
        dst_ip = random.choice(external_ips)
        log = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": config.VM_IP,
            "dst_ip": dst_ip,
            "protocol": "TCP",
            "src_port": random.randint(1024, 65535),
            "dst_port": 443,
            "packet_size": random.randint(1000, 1500),
            "memory_usage": 88.5,
            "cpu_usage": 72.3,
        }
        store.add_log(log)
        store.increment_metric("total_packets")
        store.update_metrics({"unique_ips": dst_ip})
        store.update_metrics({"protocol_counts": "TCP"})

        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": "NETWORK",
            "severity": "CRITICAL",
            "src_ip": config.VM_IP,
            "dst_ip": dst_ip,
            "protocol": "TCP",
            "reasons": [f"External destination: {dst_ip}", "Potential data exfiltration"],
            "message": f"Data exfiltration to {dst_ip}",
        }
        store.add_alert(alert)
        store.increment_metric("suspicious_events")
        store.add_suspicious_event_timestamp()
        store.add_timeline_event("NETWORK", f"Data sent to external IP: {dst_ip}", "CRITICAL")

        print(f"    [+] Packet #{i+1}: {config.VM_IP} -> {dst_ip}:443 (TCP)")
        time.sleep(0.5)

    # Phase 4: Behavioral alert
    print("\n[4/4] Generating behavioral alerts...")
    store.add_alert({
        "timestamp": datetime.now().isoformat(),
        "type": "BEHAVIORAL",
        "severity": "CRITICAL",
        "message": "MULTI-VECTOR: Data exfiltration pattern detected - file creation + network + high memory",
        "reasons": ["Data exfiltration pattern"],
    })
    store.update_metrics({"threat_score": 85, "status": "UNDER ATTACK"})
    store.add_timeline_event("BEHAVIORAL", "Data exfiltration attack confirmed", "CRITICAL")

    print("\n[✓] Data exfiltration simulation complete!")


def simulate_malware_drop(store):
    """
    Scenario 2: Malware Drop
    - Suspicious file creation (.exe, .dll, .bat, .ps1)
    - Rapid file activity
    """
    print("\n[*] Starting Scenario: MALWARE DROP")
    print("[*] Simulating malware file drops...\n")

    malware_files = [
        ("trojan.exe", ".exe", "CRITICAL"),
        ("backdoor.dll", ".dll", "CRITICAL"),
        ("persistence.bat", ".bat", "CRITICAL"),
        ("payload.ps1", ".ps1", "CRITICAL"),
        ("dropper.scr", ".scr", "WARNING"),
        ("config.reg", ".reg", "WARNING"),
    ]

    os.makedirs(config.SHARED_FOLDER_PATH, exist_ok=True)
    for fname, ext, severity in malware_files:
        fpath = os.path.join(config.SHARED_FOLDER_PATH, fname)
        with open(fpath, "w") as f:
            f.write("SIMULATED_MALWARE_" * 50)

        log = {
            "timestamp": datetime.now().isoformat(),
            "type": "FILE",
            "event": "FILE_CREATED",
            "filename": fname,
            "filepath": fpath,
            "extension": ext,
            "file_size": random.randint(50000, 5000000),
            "suspicious": True,
            "severity": severity,
        }
        store.add_log(log)
        store.add_timeline_event("FILE", f"Malware dropped: {fname}", severity)

        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": "FILE",
            "severity": severity,
            "filename": fname,
            "extension": ext,
            "reasons": [f"Suspicious extension: {ext}", f"Malware file: {fname}"],
            "message": f"Malware file detected: {fname} ({ext})",
        }
        store.add_alert(alert)
        store.increment_metric("suspicious_events")
        store.add_suspicious_event_timestamp()

        print(f"    [+] Dropped: {fname} [{severity}]")
        time.sleep(1)

    store.update_metrics({"threat_score": 70, "status": "UNDER ATTACK"})
    print("\n[✓] Malware drop simulation complete!")


def simulate_beacon_c2(store):
    """
    Scenario 3: C2 Beaconing
    - Repeated connections to same external IP
    - Regular intervals (beaconing pattern)
    """
    print("\n[*] Starting Scenario: C2 BEACONING")
    print("[*] Simulating Command & Control beaconing...\n")

    c2_server = "198.51.100.42"
    c2_port = 4444  # Metasploit default

    for i in range(20):
        log = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": config.VM_IP,
            "dst_ip": c2_server,
            "protocol": "TCP",
            "src_port": random.randint(1024, 65535),
            "dst_port": c2_port,
            "packet_size": random.randint(64, 256),
            "memory_usage": store.metrics.get("memory_usage", 45),
            "cpu_usage": store.metrics.get("cpu_usage", 35),
        }
        store.add_log(log)
        store.increment_metric("total_packets")
        store.update_metrics({"unique_ips": c2_server})
        store.update_metrics({"protocol_counts": "TCP"})

        if i >= 4:  # After threshold
            alert = {
                "timestamp": datetime.now().isoformat(),
                "type": "NETWORK",
                "severity": "CRITICAL",
                "src_ip": config.VM_IP,
                "dst_ip": c2_server,
                "protocol": "TCP",
                "port": c2_port,
                "reasons": [
                    f"Beaconing to {c2_server}",
                    f"Suspicious port: {c2_port}",
                    "C2 communication pattern",
                ],
                "message": f"C2 beaconing: {config.VM_IP} -> {c2_server}:{c2_port}",
            }
            store.add_alert(alert)
            store.increment_metric("suspicious_events")
            store.add_suspicious_event_timestamp()

        store.add_timeline_event(
            "NETWORK",
            f"Beacon #{i+1}: {config.VM_IP} -> {c2_server}:{c2_port}",
            "CRITICAL" if i >= 4 else "WARNING",
        )

        print(f"    [+] Beacon #{i+1}: {config.VM_IP} -> {c2_server}:{c2_port}")
        time.sleep(random.uniform(2, 4))  # Regular interval beaconing

    store.update_metrics({"threat_score": 90, "status": "UNDER ATTACK"})
    store.add_timeline_event("BEHAVIORAL", "C2 beaconing pattern confirmed", "CRITICAL")
    print("\n[✓] C2 beaconing simulation complete!")


def simulate_full_attack(store):
    """
    Scenario 4: Full Attack Chain
    Runs all scenarios in sequence to simulate a complete attack.
    """
    print("\n" + "=" * 55)
    print("  FULL ATTACK CHAIN SIMULATION")
    print("  Running all attack scenarios sequentially...")
    print("=" * 55)

    store.add_timeline_event("SYSTEM", "Full attack simulation started", "WARNING")

    print("\n--- Phase 1: Initial Compromise (Malware Drop) ---")
    simulate_malware_drop(store)
    time.sleep(3)

    print("\n--- Phase 2: C2 Establishment (Beaconing) ---")
    simulate_beacon_c2(store)
    time.sleep(3)

    print("\n--- Phase 3: Data Exfiltration ---")
    simulate_data_exfiltration(store)

    # Final status
    store.update_metrics({"threat_score": 95, "status": "UNDER ATTACK"})
    store.add_timeline_event("BEHAVIORAL", "FULL ATTACK CHAIN DETECTED - System compromised", "CRITICAL")
    store.persist_all()

    print("\n" + "=" * 55)
    print("  FULL ATTACK SIMULATION COMPLETE")
    print(f"  Threat Score: 95%")
    print(f"  Status: UNDER ATTACK")
    print("=" * 55)


def main():
    banner()

    scenario = "full_attack"
    if len(sys.argv) > 1:
        scenario = sys.argv[1]

    store = DataStore()

    scenarios = {
        "data_exfiltration": simulate_data_exfiltration,
        "malware_drop": simulate_malware_drop,
        "beacon_c2": simulate_beacon_c2,
        "full_attack": simulate_full_attack,
        "1": simulate_data_exfiltration,
        "2": simulate_malware_drop,
        "3": simulate_beacon_c2,
        "4": simulate_full_attack,
    }

    if scenario not in scenarios:
        print(f"Unknown scenario: {scenario}")
        print("Available: data_exfiltration, malware_drop, beacon_c2, full_attack")
        sys.exit(1)

    print(f"[*] Running scenario: {scenario}")
    scenarios[scenario](store)

    # Persist all data
    store.persist_all()
    print("\n[*] All data persisted to data/ directory.")
    print("[*] Check the dashboard at http://localhost:8501")


if __name__ == "__main__":
    main()
