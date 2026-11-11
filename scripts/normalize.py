"""Read every tool's raw JSON and write one common list of findings."""
import glob, json, os, sys

SONAR_CWE = {"S3649": "CWE-89", "S5147": "CWE-943", "S5131": "CWE-79", "S5247": "CWE-79",
             "S5146": "CWE-601", "S5144": "CWE-918", "S2083": "CWE-22", "S6096": "CWE-22",
             "S2076": "CWE-78", "S5334": "CWE-94", "S1523": "CWE-95", "S2755": "CWE-611",
             "S4790": "CWE-328", "S2068": "CWE-798", "S6418": "CWE-798", "S5122": "CWE-942"}
HOTSPOT_CWE = {"sql-injection": "CWE-89", "xss": "CWE-79", "weak-cryptography": "CWE-327",
               "auth": "CWE-798", "insecure-conf": "CWE-16", "open-redirect": "CWE-601",
               "ssrf": "CWE-918", "command-injection": "CWE-78", "code-injection": "CWE-94",
               "path-traversal-injection": "CWE-22", "xxe": "CWE-611", "cors": "CWE-942"}


def finding(tool, approach, rule, cwe, severity, location, title):
    cwe = str(cwe or "").split(":")[0].strip().upper()
    if cwe and cwe != "-1" and not cwe.startswith("CWE-"):
        cwe = "CWE-" + cwe
    return {"tool": tool, "approach": approach, "rule": str(rule), "cwe": cwe if cwe != "-1" else "",
            "severity": str(severity).upper(), "location": location, "title": str(title)[:150]}


def semgrep(data, tool):
    for r in data.get("results", []):
        cwe = r["extra"].get("metadata", {}).get("cwe", "")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else ""
        path = r["path"].split("target/", 1)[-1]
        yield finding(tool, "SAST", r["check_id"].split(".")[-1], cwe, r["extra"]["severity"],
                      f'{path}:{r["start"]["line"]}', r["extra"]["message"])


def zap(data):
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            for inst in a.get("instances", [])[:3]:
                path = "/" + inst["uri"].split("://", 1)[-1].split("/", 1)[-1]
                yield finding("zap", "DAST", a["pluginid"], a.get("cweid"), a["riskdesc"].split()[0],
                              path, a["alert"])


def trivy(data):
    for res in data.get("Results", []):
        for v in res.get("Vulnerabilities") or []:
            yield finding("trivy", "SCA", v["VulnerabilityID"], (v.get("CweIDs") or [""])[0],
                          v["Severity"], f'{v["PkgName"]}@{v["InstalledVersion"]}', v.get("Title", ""))


def npm(data):
    for name, v in data.get("vulnerabilities", {}).items():
        for via in v["via"]:
            if isinstance(via, dict):
                yield finding("npm-audit", "SCA", via.get("source"), (via.get("cwe") or [""])[0],
                              v["severity"], name, via.get("title", ""))


def sonar_issues(data):
    for i in data.get("issues", []):
        key = i["rule"].split(":")[-1]
        yield finding("sonarqube", "SAST", key, SONAR_CWE.get(key, ""), i.get("severity", ""),
                      f'{i["component"].split(":", 1)[-1]}:{i.get("line", 0)}', i["message"])


def sonar_hotspots(data):
    for h in data.get("hotspots", []):
        yield finding("sonarqube", "SAST", h.get("ruleKey", "").split(":")[-1],
                      HOTSPOT_CWE.get(h.get("securityCategory", ""), ""),
                      h.get("vulnerabilityProbability", ""),
                      f'{h["component"].split(":", 1)[-1]}:{h.get("line", 0)}', h["message"])


PARSERS = {"semgrep-baseline": lambda d: semgrep(d, "semgrep"),
           "semgrep-custom": lambda d: semgrep(d, "semgrep-custom"),
           "zap-auth": zap, "trivy-fs": trivy, "npm-audit": npm,
           "sonar-issues": sonar_issues, "sonar-hotspots": sonar_hotspots}

raw_dir, out_file = sys.argv[1], sys.argv[2]
findings = []
for path in glob.glob(os.path.join(raw_dir, "**", "*.json"), recursive=True):
    name = os.path.basename(path)[:-5]
    try:
        data = json.load(open(path, encoding="utf-8"))
    except ValueError:
        print(f"skipped (not valid JSON): {path}")
        continue
    if name in PARSERS:
        found = list(PARSERS[name](data))
    elif name.startswith("custom-"):
        found = data
    else:
        continue
    print(f"{name}: {len(found)} findings")
    findings += found

unique = list({(f["tool"], f["rule"], f["location"]): f for f in findings}.values())
os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
json.dump(unique, open(out_file, "w", encoding="utf-8"), indent=2)
print(f"TOTAL: {len(unique)} unique findings -> {out_file}")
