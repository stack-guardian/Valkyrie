from flask import Flask, jsonify, send_file, abort, request, Response, render_template_string
import os, json, time, html, sys
from typing import List, Dict, Any
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..", "watcher")))
from scanning_modes import list_modes, get_mode_config

# Paths
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
REPORTS_DIR = os.path.join(ROOT, "reports")
QUARANTINE_DIR = os.path.join(ROOT, "quarantine")
PROCESSED_DIR = os.path.join(ROOT, "processed")
CONFIG_DIR = os.path.join(ROOT, "config")
SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.json")
YARA_RULES_DIR = os.path.join(ROOT, "yara_rules")

# Ensure directories exist
for d in (CONFIG_DIR, REPORTS_DIR, QUARANTINE_DIR, PROCESSED_DIR):
    os.makedirs(d, exist_ok=True)

app = Flask(__name__)

# Configuration
REPORTS_PER_PAGE = 15

def load_settings() -> Dict[str, Any]:
    defaults = {
        "scanning_mode": "medium",
        "recursive_monitoring": False,
        "watch_path": "~/Downloads",
        "max_file_size_mb": 500,
        "auto_quarantine": True,
        "desktop_notifications": True,
        "archive_inspection": True
    }
    if os.path.isfile(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r") as f:
                data = json.load(f)
                defaults.update({k: data.get(k, v) for k, v in defaults.items()})
        except Exception:
            pass
    return defaults

def save_settings(data: Dict[str, Any]):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(data, f, indent=2)


# Single-page dashboard template rendered via Jinja.
INDEX_HTML = """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\"/>
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>
  <title>Valkyrie Dashboard</title>
  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">
  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>
  <link href=\"https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600&display=swap\" rel=\"stylesheet\">
  <style>
    :root {
      --bg: #0d1224;
      --panel: #0f1a30;
      --card: rgba(255,255,255,0.03);
      --border: rgba(255,255,255,0.08);
      --text: #e6edf7;
      --muted: #9aa7bd;
      --accent: #3bd5c7;
      --accent-2: #ffb454;
      --allow: #35d48a;
      --review: #f6c344;
      --quarantine: #ff6b6b;
      --shadow: 0 20px 60px rgba(0,0,0,0.35);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: 'Space Grotesk', system-ui, -apple-system, sans-serif;
      background: radial-gradient(circle at 20% 20%, rgba(59,213,199,0.12), transparent 35%),
                  radial-gradient(circle at 80% 0%, rgba(255,107,107,0.12), transparent 35%),
                  linear-gradient(135deg, #0b1020 0%, #111a2f 50%, #0b1020 100%);
      color: var(--text);
    }
    header {
      padding: 24px 20px 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      position: sticky;
      top: 0;
      backdrop-filter: blur(10px);
      background: linear-gradient(180deg, rgba(13,18,36,0.9) 0%, rgba(13,18,36,0.6) 100%);
      border-bottom: 1px solid var(--border);
      z-index: 10;
    }
    .brand { display:flex; align-items:center; gap:10px; }
    .brand .dot { width:12px; height:12px; border-radius:50%; background:var(--accent); box-shadow:0 0 18px rgba(59,213,199,0.8); }
    h1 { margin: 0; font-size: 22px; letter-spacing: -0.01em; }
    main { padding: 12px 20px 28px; max-width: 1200px; margin: 0 auto; }
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 16px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 14px; box-shadow: var(--shadow); backdrop-filter: blur(6px); }
    .card h3 { margin: 0; font-size: 13px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
    .card .value { margin-top: 6px; font-size: 24px; font-weight: 600; }
    .toolbar { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 14px; align-items: center; }
    .input, .select { background: var(--panel); border: 1px solid var(--border); color: var(--text); padding: 10px 12px; border-radius: 10px; outline: none; }
    .input { min-width: 220px; }
    .select { min-width: 150px; }
    .btn { background: linear-gradient(135deg, var(--accent), #1ec9b4); color: #04101a; border: none; border-radius: 10px; padding: 10px 14px; font-weight: 700; cursor: pointer; box-shadow: 0 10px 30px rgba(59,213,199,0.35); transition: transform 0.1s ease, box-shadow 0.2s ease; }
    .btn:hover { transform: translateY(-1px); box-shadow: 0 12px 32px rgba(59,213,199,0.45); }
    .meta { color: var(--muted); font-size: 13px; }
    .table-wrap { background: var(--card); border:1px solid var(--border); border-radius: 14px; overflow: hidden; box-shadow: var(--shadow); }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px 14px; text-align: left; border-bottom: 1px solid var(--border); font-size: 14px; }
    th { background: rgba(255,255,255,0.02); color: var(--muted); letter-spacing: 0.04em; text-transform: uppercase; font-size: 12px; }
    tr:hover td { background: rgba(255,255,255,0.02); }
    .mono { font-family: "JetBrains Mono", "SFMono-Regular", Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 13px; }
    .badge { display:inline-flex; align-items:center; gap:6px; padding:6px 10px; border-radius: 999px; font-weight:600; font-size: 12px; letter-spacing: 0.02em; }
    .badge.allow { background: rgba(53,212,138,0.15); color: var(--allow); border:1px solid rgba(53,212,138,0.35); }
    .badge.review { background: rgba(246,195,68,0.15); color: var(--review); border:1px solid rgba(246,195,68,0.35); }
    .badge.quarantine { background: rgba(255,107,107,0.15); color: var(--quarantine); border:1px solid rgba(255,107,107,0.35); }
    .pill { display:inline-block; padding:6px 10px; border-radius: 10px; background: rgba(255,255,255,0.04); border:1px solid var(--border); color: var(--muted); font-size: 12px; }
    .pagination { display: flex; gap: 8px; padding: 12px 14px; align-items: center; justify-content: flex-end; background: rgba(255,255,255,0.02); }
    .page-btn { background: var(--panel); color: var(--text); border:1px solid var(--border); border-radius: 8px; padding: 8px 12px; cursor: pointer; }
    .page-btn[disabled] { opacity: 0.4; cursor: not-allowed; }
    .empty { padding: 32px; text-align: center; color: var(--muted); }
    @media (max-width: 720px) {
      header, main { padding: 16px; }
      .table-wrap { overflow-x: auto; }
      th, td { white-space: nowrap; }
      h1 { font-size: 18px; }
    }
  </style>
</head>
<body>
  <header>
    <div class=\"brand\">
      <span class=\"dot\"></span>
      <div>
        <h1>Valkyrie Dashboard</h1>
        <div class=\"meta\">Reports folder: {{ reports_dir }}</div>
      </div>
    </div>
    <button class=\"btn\" id=\"refresh-btn\">Refresh</button>
  </header>

  <main>
    <div class=\"cards\">
      <div class=\"card\"><h3>Total Reports</h3><div class=\"value\" id=\"stat-total\">0</div></div>
      <div class=\"card\"><h3>Quarantine</h3><div class=\"value\" id=\"stat-quarantine\">0</div></div>
      <div class=\"card\"><h3>Review</h3><div class=\"value\" id=\"stat-review\">0</div></div>
      <div class=\"card\"><h3>Allow</h3><div class=\"value\" id=\"stat-allow\">0</div></div>
    </div>

    <div class=\"toolbar\">
      <input class=\"input\" id=\"search\" placeholder=\"Search by name or hash prefix\" autocomplete=\"off\" />
      <select class=\"select\" id=\"verdict-filter\">
        <option value=\"all\">All verdicts</option>
        <option value=\"quarantine\">Quarantine</option>
        <option value=\"review\">Review</option>
        <option value=\"allow\">Allow</option>
      </select>
      <span class=\"pill\" id=\"updated-at\">Waiting for data…</span>
    </div>

    <div class=\"table-wrap\">
      <table>
        <thead>
          <tr>
            <th>SHA256 (12)</th>
            <th>File</th>
            <th>MIME</th>
            <th>Verdict</th>
            <th>Scanned</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody id=\"table-body\">
          <tr><td colspan=\"6\" class=\"empty\">Loading reports…</td></tr>
        </tbody>
      </table>
      <div class=\"pagination\" id=\"pager\" hidden>
        <button class=\"page-btn\" id=\"prev-page\">Prev</button>
        <span class=\"meta\" id=\"page-info\"></span>
        <button class=\"page-btn\" id=\"next-page\">Next</button>
      </div>
    </div>
  </main>

  <script>
    const pageSize = {{ per_page }};
    let page = 1;
    let verdict = 'all';
    let search = '';

    const tbody = document.getElementById('table-body');
    const verdictFilter = document.getElementById('verdict-filter');
    const searchInput = document.getElementById('search');
    const pager = document.getElementById('pager');
    const pageInfo = document.getElementById('page-info');
    const prevBtn = document.getElementById('prev-page');
    const nextBtn = document.getElementById('next-page');
    const updatedAt = document.getElementById('updated-at');

    const statTotal = document.getElementById('stat-total');
    const statQ = document.getElementById('stat-quarantine');
    const statR = document.getElementById('stat-review');
    const statA = document.getElementById('stat-allow');

    const esc = function(s){
      s = s || '';
      const map = {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"};
      return s.replace(/[&<>"']/g, function(c){ return map[c] || c; });
    };

    function pickVerdict(r){
      if (r && r.scoring && r.scoring.verdict) return r.scoring.verdict;
      if (r && r.verdict) return r.verdict;
      return 'unknown';
    }

    async function loadStats() {
      try {
        const res = await fetch('/api/stats');
        const stats = await res.json();
        statTotal.textContent = stats.total;
        statQ.textContent = stats.by_verdict.quarantine;
        statR.textContent = stats.by_verdict.review;
        statA.textContent = stats.by_verdict.allow;
      } catch (err) {
        console.error('stats', err);
      }
    }

    async function loadReports() {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">Loading reports…</td></tr>';
      const params = new URLSearchParams({
        page: page,
        per_page: pageSize,
        verdict: verdict,
        search: search,
        sort_by: 'timestamp',
        sort_order: 'desc'
      });
      try {
        const res = await fetch('/api/reports?' + params.toString());
        const payload = await res.json();
        renderTable(payload.reports, payload.page, payload.pages, payload.total);
        updatedAt.textContent = 'Updated ' + new Date().toLocaleTimeString();
      } catch (err) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">Failed to load reports</td></tr>';
        updatedAt.textContent = 'Load failed';
        console.error(err);
      }
    }

    function badge(v) {
      const verdict = (v || '').toLowerCase();
      return '<span class="badge ' + esc(verdict) + '">' + (verdict || '?').toUpperCase() + '</span>';
    }

    function formatDate(ts) {
      if (!ts) return '–';
      try { return new Date(ts * 1000).toLocaleString(); } catch (e) { return '–'; }
    }

    function renderTable(rows, currentPage, totalPages, total) {
      if (!rows || !rows.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No reports match your filters.</td></tr>';
        pager.hidden = true;
        return;
      }

      tbody.innerHTML = rows.map(function(r){
        const sha = esc((r.sha256 || '').slice(0,12));
        const name = esc(r.name || '');
        const mime = esc(r.mime || '');
        const verdictVal = pickVerdict(r);
        const verdictHtml = badge(verdictVal);
        const when = esc(formatDate(r.timestamp));
        const jsonFile = esc(r._file || '');
        return '<tr>' +
          '<td class="mono">' + (sha || '–') + '</td>' +
          '<td>' + name + '</td>' +
          '<td>' + mime + '</td>' +
          '<td>' + verdictHtml + '</td>' +
          '<td>' + when + '</td>' +
          '<td><a href="/api/report/' + jsonFile + '" target="_blank" style="color:var(--accent)">JSON</a></td>' +
        '</tr>';
      }).join('');

      pager.hidden = totalPages <= 1;
      pageInfo.textContent = 'Page ' + currentPage + ' of ' + totalPages + ' • ' + total + ' total';
      prevBtn.disabled = currentPage <= 1;
      nextBtn.disabled = currentPage >= totalPages;
    }

    verdictFilter.addEventListener('change', function(e){ verdict = e.target.value; page = 1; loadReports(); loadStats(); });
    searchInput.addEventListener('input', function(){
      clearTimeout(searchInput._t);
      searchInput._t = setTimeout(function(){ search = searchInput.value.trim(); page = 1; loadReports(); }, 150);
    });
    document.getElementById('refresh-btn').addEventListener('click', function(){ loadReports(); loadStats(); });
    prevBtn.addEventListener('click', function(){ if (page > 1) { page -= 1; loadReports(); }});
    nextBtn.addEventListener('click', function(){ page += 1; loadReports(); });

    loadReports();
    loadStats();
  </script>
</body>
</html>
"""

def load_reports() -> List[Dict[str, Any]]:
    """
    Load all reports from the reports directory.

    Returns:
        List of report dictionaries
    """
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

def filter_reports(reports: List[Dict[str, Any]], filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Filter reports based on criteria.

    Args:
        reports: List of reports
        filters: Filter criteria

    Returns:
        Filtered list of reports
    """
    filtered = reports

    # Filter by verdict
    if "verdict" in filters and filters["verdict"] and filters["verdict"] != "all":
        verdict = filters["verdict"].lower()
        filtered = [
            r for r in filtered
            if (r.get("scoring", {}).get("verdict") or r.get("verdict", "")).lower() == verdict
        ]

    # Filter by search query
    if "search" in filters and filters["search"]:
        query = filters["search"].lower()
        filtered = [
            r for r in filtered
            if query in r.get("name", "").lower()
            or query in r.get("sha256", "").lower()
            or any(query in hit.lower() for hit in r.get("yara", {}).get("hits", []))
        ]

    return filtered

def sort_reports(reports: List[Dict[str, Any]], sort_by: str = "timestamp", sort_order: str = "desc") -> List[Dict[str, Any]]:
    """
    Sort reports by specified criteria.

    Args:
        reports: List of reports
        sort_by: Field to sort by
        sort_order: Sort order (asc or desc)

    Returns:
        Sorted list of reports
    """
    reverse = sort_order == "desc"

    if sort_by == "timestamp":
        return sorted(reports, key=lambda r: r.get("timestamp", 0), reverse=reverse)
    elif sort_by == "name":
        return sorted(reports, key=lambda r: r.get("name", "").lower(), reverse=reverse)
    elif sort_by == "score":
        return sorted(reports, key=lambda r: r.get("scoring", {}).get("total_score", 0), reverse=reverse)
    elif sort_by == "verdict":
        verdict_order = {"quarantine": 0, "review": 1, "allow": 2}
        return sorted(
            reports,
            key=lambda r: verdict_order.get(
                (r.get("scoring", {}).get("verdict") or r.get("verdict", "allow")).lower(),
                3
            ),
            reverse=reverse
        )

    return reports

@app.get("/api/reports")
def api_reports():
    """
    API endpoint to get reports with filtering and pagination.
    """
    reports = load_reports()

    # Extract query parameters
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", REPORTS_PER_PAGE))
    search = request.args.get("search", "")
    verdict = request.args.get("verdict", "all")
    sort_by = request.args.get("sort_by", "timestamp")
    sort_order = request.args.get("sort_order", "desc")

    # Apply filters
    filters = {
        "search": search,
        "verdict": verdict
    }
    filtered = filter_reports(reports, filters)

    # Sort reports
    sorted_reports = sort_reports(filtered, sort_by, sort_order)

    # Paginate
    total = len(sorted_reports)
    start = (page - 1) * per_page
    end = start + per_page
    page_reports = sorted_reports[start:end]

    return jsonify({
        "reports": page_reports,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page
    })

@app.get("/api/stats")
def api_stats():
    """
    API endpoint to get dashboard statistics.
    """
    reports = load_reports()

    stats = {
        "total": len(reports),
        "by_verdict": {
            "quarantine": 0,
            "review": 0,
            "allow": 0
        },
        "recent_scans": 0,
        "last_scan": None
    }

    now = time.time()
    last_24h = now - 86400

    for r in reports:
        verdict = (r.get("scoring", {}).get("verdict") or r.get("verdict", "unknown"))
        if verdict in stats["by_verdict"]:
            stats["by_verdict"][verdict] += 1

        if r.get("timestamp", 0) > last_24h:
            stats["recent_scans"] += 1

        if stats["last_scan"] is None or r.get("timestamp", 0) > stats["last_scan"]:
            stats["last_scan"] = r.get("timestamp")

    return jsonify(stats)

@app.get("/api/stream")
def api_stream():
    """
    Server-Sent Events endpoint for real-time updates.
    """
    def generate():
        last_mtime = 0
        while True:
            try:
                if os.path.exists(REPORTS_DIR):
                    current_mtime = os.path.getmtime(REPORTS_DIR)
                    if current_mtime > last_mtime:
                        last_mtime = current_mtime
                        yield f"event: update\ndata: {json.dumps({'status': 'update'})}\n\n"

                time.sleep(2)
            except Exception as e:
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                            "X-Accel-Buffering": "no"})


@app.get("/api/settings")
def api_get_settings():
    return jsonify({
        "settings": load_settings(),
        "modes": list_modes()
    })


@app.post("/api/settings")
def api_update_settings():
    incoming = request.get_json(force=True, silent=True) or {}
    current = load_settings()
    for k, v in incoming.items():
        if k in current:
            current[k] = v
    save_settings(current)
    return jsonify({"ok": True, "settings": current})


@app.post("/api/restore")
def api_restore():
    data = request.get_json(force=True, silent=True) or {}
    fname = data.get("file")
    if not fname:
        abort(400)

    quarantine_path = os.path.join(QUARANTINE_DIR, fname)
    if not os.path.isfile(quarantine_path):
        abort(404)

    # Try to find original path from report
    report_file = None
    for rf in os.listdir(REPORTS_DIR):
        if fname in rf:
            report_file = os.path.join(REPORTS_DIR, rf)
            break

    target = os.path.expanduser("~/Downloads")
    if report_file:
        try:
            with open(report_file) as f:
                rep = json.load(f)
                orig = rep.get("path")
                if orig:
                    target = os.path.dirname(orig)
        except Exception:
            pass

    os.makedirs(target, exist_ok=True)
    dest = os.path.join(target, fname)
    shutil.move(quarantine_path, dest)

    return jsonify({"ok": True, "restored_to": dest})

@app.get("/api/report/<name>")
def api_report(name):
    path = os.path.join(REPORTS_DIR, name)
    if os.path.isfile(path):
        return send_file(path, mimetype="application/json")
    abort(404)

@app.get("/")
def index():
    return render_template_string(
        INDEX_HTML,
        reports_dir=html.escape(REPORTS_DIR),
        per_page=REPORTS_PER_PAGE,
    )


if __name__ == "__main__":
    print("Valkyrie Enhanced Dashboard starting on http://127.0.0.1:5000 ...")
    print("\nFeatures:")
    print("  ✨ Real-time updates via Server-Sent Events")
    print("  🔍 Search and filtering")
    print("  📊 Sort by time, name, score, verdict")
    print("  📋 Detailed report view with score visualization")
    print("  📱 Responsive design")
    print("  🎨 Modern dark theme UI\n")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
