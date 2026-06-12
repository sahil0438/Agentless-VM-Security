"""Check what external IPs are being captured."""
import requests

r = requests.get("http://localhost:8000/dashboard-data")
d = r.json()
metrics = d.get("status", {})
all_ips = metrics.get("unique_ip_list", [])
ext_ips = [
    ip for ip in all_ips
    if not ip.startswith(("192.168.", "10.", "172.", "127.", "0.0.0.0", "255."))
]
print(f"Total unique IPs: {len(all_ips)}")
print(f"External IPs: {len(ext_ips)}")
print("First 20 external IPs:")
for ip in ext_ips[:20]:
    print(f"  {ip}")
