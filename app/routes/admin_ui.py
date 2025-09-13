# ruff: noqa: E501
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/admin/ui", tags=["admin-ui"])

_HTML = """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <title>Guardrail Admin — Active Policy</title>
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <style>
    :root { --bg:#0b0e14; --card:#121724; --text:#e6e6e6; --muted:#9aa4b2; --accent:#53b1fd; --ok:#34d399; --warn:#f59e0b; --bad:#ef4444; }
    html,body { margin:0; padding:0; background:var(--bg); color:var(--text); font:14px/1.4 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; }
    header { padding:18px 20px; border-bottom:1px solid #1e2635; display:flex; align-items:center; gap:10px; }
    h1 { font-size:18px; margin:0; }
    .container { max-width:1100px; margin:24px auto; padding:0 20px; display:grid; grid-template-columns: 1fr 1fr; gap:16px; }
    .card { background:var(--card); border:1px solid #1e2635; border-radius:16px; padding:16px; box-shadow:0 4px 16px rgba(0,0,0,.25); }
    .card h2 { margin:0 0 10px; font-size:16px; }
    .kv { display:grid; grid-template-columns: 220px 1fr; gap:8px 12px; }
    .kv div { padding:6px 8px; border-radius:8px; background:#0e1420; }
    .tag { display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; background:#0e1420; border:1px solid #253248; color:var(--muted); }
    .grid { display:grid; gap:8px; }
    .muted { color:var(--muted); }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    pre { margin:0; overflow:auto; background:#0d1320; border:1px solid #1e2635; border-radius:12px; padding:12px; }
    .footer { margin: 8px 20px 24px; color: var(--muted); font-size: 12px; }
    .pill { padding:4px 10px; border-radius:999px; border:1px solid #2a364c; background:#0d1320; color:#b6c2d0; }
    .row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .login { display:flex; gap:8px; align-items:center; }
    .input { background:#0d1320; border:1px solid #253248; color:#dbe6f3; border-radius:10px; padding:6px 10px; }
    .btn { background:#172033; color:#dbe6f3; border:1px solid #253248; border-radius:10px; padding:6px 10px; cursor:pointer; }
    @media (max-width: 900px) { .container { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header>
    <div class=\"pill\">Guardrail Admin</div>
    <h1>Active Policy</h1>
    <div class=\"row\" style=\"margin-left:auto\">
      <span class=\"muted\">Read-only · v2</span>
    </div>
  </header>

  <div class=\"container\">
    <section class=\"card\" id=\"policyCard\">
      <h2>Policy Overview</h2>
      <div class=\"kv\" id=\"policyKv\">
        <div>Policy Version</div><div id=\"policyVersion\"><span class=\"muted\">loading…</span></div>
        <div>Clarify HTTP Status</div><div id=\"clarifyStatus\"><span class=\"muted\">loading…</span></div>
      </div>
    </section>

    <section class=\"card\">
      <h2>Env Toggles</h2>
      <div class=\"grid\" id=\"envList\"><span class=\"muted\">loading…</span></div>
    </section>

    <section class=\"card\" style=\"grid-column: 1 / -1;\">
      <h2>Decision Map</h2>
      <pre id=\"decisionMap\"><span class=\"muted\">loading…</span></pre>
    </section>

    <section class=\"card\" style=\"grid-column: 1 / -1;\">
      <h2>Preview (Dry-Run)</h2>
      <div class=\"grid\" style=\"gap:6px\">
        <div class=\"row login\">
          <label class=\"muted\">Admin token</label>
          <input id=\"token\" class=\"input\" type=\"password\" placeholder=\"paste token (optional)\">
          <button class=\"btn\" onclick=\"saveToken()\">Save</button>
          <button class=\"btn\" onclick=\"clearToken()\">Clear</button>
        </div>
        <textarea id=\"overrides\" class=\"input\" rows=\"4\" placeholder='{"EGRESS_SUMMARIZE_ENABLED":"1"}'></textarea>
        <div class=\"row\">
          <button class=\"btn\" onclick=\"runPreview()\">Preview</button>
        </div>
        <pre id=\"previewOut\"><span class=\"muted\">no preview yet</span></pre>
      </div>
    </section>

    <section class=\"card\" style=\"grid-column: 1 / -1;\">
      <h2>Raw</h2>
      <pre id=\"raw\"><span class=\"muted\">loading…</span></pre>
    </section>
  </div>

  <div class=\"footer\">
    Admin JSON endpoints may require Bearer auth if enabled (ADMIN_UI_AUTH=1). Token is stored in localStorage only in this browser. · Hybrid-05
  </div>

  <script>
    function getToken(){ return localStorage.getItem('admin_ui_token') || ''; }
    function saveToken(){ const v = document.getElementById('token').value; localStorage.setItem('admin_ui_token', v || ''); fetchActive(); }
    function clearToken(){ localStorage.removeItem('admin_ui_token'); document.getElementById('token').value=''; fetchActive(); }

    async function fetchJSON(url, opts={}) {
      const headers = Object.assign({"Accept":"application/json"}, opts.headers || {});
      const tok = getToken();
      if (tok) headers["Authorization"] = "Bearer " + tok;
      const r = await fetch(url, { ...opts, headers });
      if (!r.ok) throw new Error(r.status + " " + (await r.text()));
      return await r.json();
    }

    async function fetchActive() {
      try {
        const data = await fetchJSON('/admin/policies/active');
        render(data);
      } catch (e) {
        document.getElementById('raw').textContent = String(e);
      }
    }

    async function runPreview() {
      const txt = document.getElementById('overrides').value.trim();
      let overrides = {};
      if (txt) { try { overrides = JSON.parse(txt); } catch(e){ document.getElementById('previewOut').textContent = 'Invalid JSON'; return; } }
      try {
        const data = await fetchJSON('/admin/policies/preview', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ env_overrides: overrides })
        });
        document.getElementById('previewOut').textContent = JSON.stringify(data, null, 2);
      } catch (e) {
        document.getElementById('previewOut').textContent = String(e);
      }
    }

    function render(data) {
      const policyVersion = document.getElementById('policyVersion');
      const clarifyStatus = document.getElementById('clarifyStatus');
      const envList = document.getElementById('envList');
      const decisionMap = document.getElementById('decisionMap');
      const raw = document.getElementById('raw');

      policyVersion.textContent = String(data.policy_version ?? 'unknown');
      const cs = data?.env_toggles?.CLARIFY_HTTP_STATUS ?? '422';
      clarifyStatus.textContent = String(cs);

      envList.innerHTML = '';
      const env = data.env_toggles || {};
      Object.keys(env).sort().forEach(k => {
        const row = document.createElement('div');
        row.className = 'row';
        const key = document.createElement('span'); key.className='tag'; key.textContent = k;
        const val = document.createElement('span'); val.textContent = String(env[k]);
        row.appendChild(key); row.appendChild(val);
        envList.appendChild(row);
      });

      decisionMap.textContent = JSON.stringify(data.decision_map ?? {}, null, 2);
      raw.textContent = JSON.stringify(data, null, 2);
    }

    // Initialize token field and fetch
    document.getElementById('token').value = getToken();
    fetchActive();
  </script>
</body>
</html>"""


@router.get("", response_class=HTMLResponse)
def admin_ui_root() -> HTMLResponse:
    return HTMLResponse(_HTML)
