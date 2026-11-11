
"""Our own DAST checks: things ZAP does not test by default."""
import json, os
import requests

BASE = "http://localhost:3000"
findings = []


def add(cwe, severity, path, title):
    findings.append({"tool": "custom-dast", "approach": "DAST", "rule": title, "cwe": cwe,
                     "severity": severity, "location": path, "title": title})


# 1. Internal documents listed publicly in /ftp
r = requests.get(f"{BASE}/ftp", timeout=15)
if r.status_code == 200 and ".md" in r.text:
    add("CWE-548", "MEDIUM", "/ftp", "Directory listing exposes internal files")

# 2. Server metrics readable without logging in
r = requests.get(f"{BASE}/metrics", timeout=15)
if r.status_code == 200 and "process_cpu" in r.text:
    add("CWE-200", "MEDIUM", "/metrics", "Server metrics exposed without authentication")

# 3. A product can be changed without logging in
r = requests.put(f"{BASE}/api/Products/1", json={"description": "changed by scanner"}, timeout=15)
if r.status_code == 200:
    add("CWE-862", "HIGH", "/api/Products/1", "Product modified without authentication")

os.makedirs("results", exist_ok=True)
json.dump(findings, open("results/custom-dast.json", "w"), indent=2)
print(f"{len(findings)} custom findings")
