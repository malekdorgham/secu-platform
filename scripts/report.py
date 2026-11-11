"""Turn metrics.json into a readable HTML report."""
import json, os, sys
from jinja2 import Template

TEMPLATE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Security scan report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#1f2937}
h1{margin-bottom:4px}.sub{color:#6b7280;margin-top:0}
.kpis{display:flex;gap:12px;flex-wrap:wrap}.kpi{flex:1;min-width:150px;border:1px solid #e5e7eb;border-radius:8px;padding:12px}
.kpi b{font-size:28px;display:block}
table{border-collapse:collapse;width:100%;margin:8px 0 24px}td,th{border-bottom:1px solid #e5e7eb;padding:6px 8px;text-align:left}
th{background:#f3f4f6}.bar{background:#2563eb;height:10px;border-radius:3px}
.yes{color:#15803d;font-weight:bold}.no{color:#d1d5db}.custom{background:#fef3c7}
</style></head><body>
<h1>Security scan report</h1>
<p class="sub">Target: OWASP Juice Shop &middot; Run {{ run }}</p>
<div class="kpis">
 <div class="kpi"><b>{{ m.after.findings }}</b>findings (all tools)</div>
 <div class="kpi"><b>{{ m.truth|length }}</b>known vulnerabilities</div>
 <div class="kpi"><b>{{ (m.after.recall*100)|round|int }}%</b>found (recall)</div>
 <div class="kpi"><b>{{ (m.after.precision*100)|round|int }}%</b>precision</div>
</div>
<h2>Before vs after our custom rules</h2>
<table><tr><th></th><th>Findings</th><th>TP</th><th>FP</th><th>FN</th><th>Precision</th><th>Recall</th><th>F1</th></tr>
{% for label in ["before", "after"] %}{% set r = m[label] %}
<tr><td>{{ label }}</td><td>{{ r.findings }}</td><td>{{ r.TP }}</td><td>{{ r.FP }}</td><td>{{ r.FN }}</td>
<td>{{ r.precision }}</td><td>{{ r.recall }}</td><td>{{ r.F1 }}</td></tr>{% endfor %}</table>
{% if m.custom_only %}<p>Found <b>only</b> thanks to our custom rules: {{ m.custom_only|join(", ") }}</p>{% endif %}
<h2>Per tool</h2>
<table><tr><th>Tool</th><th>Approach</th><th>Findings</th><th>TP</th><th>FP</th><th>Precision</th><th>Recall</th><th>Recall bar</th></tr>
{% for tool, r in m.per_tool.items() %}
<tr><td>{{ tool }}</td><td>{{ approach[tool] }}</td><td>{{ r.findings }}</td><td>{{ r.TP }}</td><td>{{ r.FP }}</td>
<td>{{ r.precision }}</td><td>{{ r.recall }}</td><td><div class="bar" style="width:{{ (r.recall*200)|int }}px"></div></td></tr>{% endfor %}</table>
<h2>Per approach</h2>
<table><tr><th>Approach</th><th>Findings</th><th>TP</th><th>FP</th><th>Precision</th><th>Recall</th></tr>
{% for ap, r in m.per_approach.items() %}<tr><td>{{ ap }}</td><td>{{ r.findings }}</td><td>{{ r.TP }}</td><td>{{ r.FP }}</td>
<td>{{ r.precision }}</td><td>{{ r.recall }}</td></tr>{% endfor %}</table>
<h2>Coverage matrix: which tool found which vulnerability</h2>
<table><tr><th>Vulnerability</th>{% for t in tools %}<th>{{ t }}</th>{% endfor %}</tr>
{% for g in m.truth %}<tr><td>{{ g.id }} &ndash; {{ g.name }}</td>
{% for t in tools %}<td class="{{ 'yes' if t in g.found_by else 'no' }}{{ ' custom' if t in custom and t in g.found_by else '' }}">{{ '&#10003;' if t in g.found_by else '&middot;' }}</td>{% endfor %}</tr>{% endfor %}</table>
<h2>Missed by every tool ({{ m.missed_by_all|length }})</h2>
<ul>{% for n in m.missed_by_all %}<li>{{ n }}</li>{% endfor %}</ul>
</body></html>"""

metrics = json.load(open(sys.argv[1], encoding="utf-8"))
findings = json.load(open(sys.argv[2], encoding="utf-8"))
approach = {f["tool"]: f["approach"] for f in findings}
html = Template(TEMPLATE).render(m=metrics, tools=list(metrics["per_tool"].keys()), approach=approach,
                                 custom={"semgrep-custom", "custom-dast"},
                                 run=os.environ.get("GITHUB_RUN_NUMBER", "local"))
open(sys.argv[3], "w", encoding="utf-8").write(html)
print(f"Report written to {sys.argv[3]}")
