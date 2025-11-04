from flask import Flask, jsonify, send_file, abort
import os, json, time, html

# Paths
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
REPORTS_DIR = os.path.join(ROOT, "reports")

app = Flask(__name__)

def load_reports():
    items = []
    if not os.path.isdir(REPORTS_DIR):
        return items
    for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if f.endswith(".json"):
            path = os.path.join(REPORTS_DIR, f)
            try:
                with open(path) as fh:
                    data = json.load(fh)
                    data["_file"] = f
                    items.append(data)
            except Exception:
                pass
    return items

@app.get("/api/reports")
def api_reports():
    return jsonify(load_reports())

@app.get("/api/report/<name>")
def api_report(name):
    path = os.path.join(REPORTS_DIR, name)
    if os.path.isfile(path):
        return send_file(path, mimetype="application/json")
    abort(404)

@app.get("/")
def index():
    rows = []
    for r in load_reports():
        verdict = r.get("verdict","?")
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.get("timestamp",0)))
        fname = html.escape(r.get("name",""))
        sha = r.get("sha256","")[:12]
        json_file = html.escape(r.get("_file",""))
        color = {"allow":"#2e7d32","review":"#ef6c00","quarantine":"#c62828"}.get(verdict, "#424242")
        rows.append(f"""
          <tr>
            <td style="font-family:monospace">{sha}</td>
            <td>{fname}</td>
            <td>{r.get('mime','')}</td>
            <td style="color:{color}; font-weight:600">{verdict.upper()}</td>
            <td>{when}</td>
            <td><a href="/api/report/{json_file}" target="_blank">JSON</a></td>
          </tr>
        """)
    table = "\n".join(rows) if rows else "<tr><td colspan='6' style='color:#666'>No reports yet. Drop a file into Downloads.</td></tr>"
    return f"""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8"/>
      <title>Valkyrie Dashboard</title>
      <style>
        body {{ font-family: system-ui, Arial, sans-serif; margin: 24px; background:#fafafa; }}
        h1 {{ margin: 0 0 12px 0; }}
        .card {{ background:#fff; padding:16px; border-radius:12px; box-shadow:0 2px 10px rgba(0,0,0,0.08); }}
        table {{ width:100%; border-collapse: collapse; }}
        th, td {{ padding:10px; border-bottom:1px solid #eee; text-align:left; }}
        th {{ background:#f3f4f6; }}
        .toolbar {{ margin-bottom:12px; display:flex; gap:8px; align-items:center; }}
        .btn {{ display:inline-block; padding:8px 12px; border-radius:8px; border:1px solid #ddd; background:#fff; cursor:pointer; }}
      </style>
      <script>
        function refreshNow() {{
          location.reload();
        }}
      </script>
    </head>
    <body>
      <div class="card">
        <h1>SecureScan Dashboard</h1>
        <div class="toolbar">
          <button class="btn" onclick="refreshNow()">Refresh</button>
          <span style="color:#666">Reports folder: {html.escape(REPORTS_DIR)}</span>
        </div>
        <table>
          <thead>
            <tr>
              <th>SHA (prefix)</th>
              <th>File</th>
              <th>MIME</th>
              <th>Verdict</th>
              <th>Scanned At</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {table}
          </tbody>
        </table>
      </div>
    </body>
    </html>
    """

if __name__ == "__main__":
    print("SecureScan dashboard starting on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=False)

