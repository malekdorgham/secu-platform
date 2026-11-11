"""Compare findings with the ground truth and compute TP, FP, FN, precision, recall, F1."""
import json, sys
import yaml

findings = json.load(open(sys.argv[1], encoding="utf-8"))
truth = yaml.safe_load(open(sys.argv[2], encoding="utf-8"))
CUSTOM_TOOLS = {"semgrep-custom", "custom-dast"}


def matches(f, g):
    if f["approach"] not in g["approaches"]:
        return False
    if f["approach"] == "SCA":
        return f["location"].split("@")[0] in g.get("packages", [])
    if f["cwe"] not in g.get("cwe", []):
        return False
    if f["approach"] == "SAST":
        return any(f["location"].startswith(p + ":") for p in g.get("files", []))
    return any(e in f["location"] for e in g.get("endpoints", []))


def score(subset, approaches):
    applicable = [g for g in truth if set(g["approaches"]) & approaches]
    found = sorted({g["id"] for g in applicable for f in subset if matches(f, g)})
    tp = sum(1 for f in subset if any(matches(f, g) for g in truth))
    fp = len(subset) - tp
    fn = len(applicable) - len(found)
    precision = tp / len(subset) if subset else 0.0
    recall = len(found) / len(applicable) if applicable else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"findings": len(subset), "TP": tp, "FP": fp, "FN": fn,
            "precision": round(precision, 3), "recall": round(recall, 3), "F1": round(f1, 3),
            "found": found}


ALL = {"SAST", "DAST", "SCA"}
result = {"per_tool": {}, "per_approach": {}}
for tool in sorted({f["tool"] for f in findings}):
    subset = [f for f in findings if f["tool"] == tool]
    result["per_tool"][tool] = score(subset, {subset[0]["approach"]})
for ap in sorted(ALL):
    result["per_approach"][ap] = score([f for f in findings if f["approach"] == ap], {ap})
result["before"] = score([f for f in findings if f["tool"] not in CUSTOM_TOOLS], ALL)
result["after"] = score(findings, ALL)
result["truth"] = [{"id": g["id"], "name": g["name"], "approaches": g["approaches"],
                    "found_by": sorted({f["tool"] for f in findings if matches(f, g)})} for g in truth]
result["missed_by_all"] = [t["name"] for t in result["truth"] if not t["found_by"]]
result["custom_only"] = [t["name"] for t in result["truth"]
                         if t["found_by"] and set(t["found_by"]) <= CUSTOM_TOOLS]

json.dump(result, open(sys.argv[3], "w", encoding="utf-8"), indent=2)
for label in ("before", "after"):
    m = result[label]
    print(f'{label:6}  findings={m["findings"]}  TP={m["TP"]}  FP={m["FP"]}  FN={m["FN"]}  '
          f'precision={m["precision"]}  recall={m["recall"]}  F1={m["F1"]}')
