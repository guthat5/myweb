import os
import sqlite3
import secrets
from functools import wraps
from flask import (
    Flask, request, session, redirect, url_for,
    render_template_string, g, abort, flash
)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS_HASH = os.environ.get("ADMIN_PASS_HASH")
if not ADMIN_PASS_HASH:
    _pw = os.environ.get("ADMIN_PASSWORD", "changeme")
    ADMIN_PASS_HASH = generate_password_hash(_pw)
    print(f"⚠️  WARNING: fallback password '{_pw}' — set ADMIN_PASS_HASH!")
DB_PATH = os.environ.get("DB_PATH", "vpn.db")

# ---------- DB ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

with sqlite3.connect(DB_PATH) as _db:
    _db.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            location TEXT DEFAULT '',
            url TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

# ---------- Helpers ----------
def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper

@app.before_request
def ensure_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)

def check_csrf():
    if request.form.get("_csrf", "") != session.get("csrf"):
        abort(400, "Invalid CSRF token")

# ---------- Shared base style ----------
BASE_STYLE = """
:root{--bg-1:#050816;--accent:#38bdf8;--accent-2:#a78bfa;--text:#e2e8f0;--muted:#94a3b8;--card-bg:rgba(15,23,42,.6);--border:rgba(148,163,184,.15);--success:#22c55e;--gold:#fbbf24;--danger:#ef4444}
*{box-sizing:border-box;margin:0;padding:0}
html,body{min-height:100%}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg-1);color:var(--text);min-height:100vh;overflow-x:hidden;padding:0 16px 80px;position:relative}
body::before,body::after{content:"";position:fixed;width:600px;height:600px;border-radius:50%;filter:blur(120px);opacity:.35;z-index:-1;pointer-events:none;animation:float 18s ease-in-out infinite}
body::before{background:radial-gradient(circle,#38bdf8,transparent 70%);top:-200px;left:-200px}
body::after{background:radial-gradient(circle,#a78bfa,transparent 70%);bottom:-200px;right:-200px;animation-delay:-9s}
@keyframes float{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(40px,-30px) scale(1.1)}}
.grid-bg{position:fixed;inset:0;background-image:linear-gradient(rgba(148,163,184,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(148,163,184,.04) 1px,transparent 1px);background-size:48px 48px;z-index:-1;mask-image:radial-gradient(ellipse at center,#000 20%,transparent 80%);-webkit-mask-image:radial-gradient(ellipse at center,#000 20%,transparent 80%);pointer-events:none}
.wrap{max-width:820px;margin:0 auto;padding-top:64px}
header{text-align:center;margin-bottom:48px;animation:fadeDown .8s cubic-bezier(.22,.61,.36,1) both}
.badge{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;background:rgba(56,189,248,.1);border:1px solid rgba(56,189,248,.3);border-radius:999px;font-size:.72em;font-weight:600;color:var(--accent);letter-spacing:1.5px;margin-bottom:24px;backdrop-filter:blur(10px);text-transform:uppercase}
.badge .dot{width:6px;height:6px;border-radius:50%;background:var(--success);box-shadow:0 0 10px var(--success);animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.85)}}
.brand{font-family:'Cinzel',serif;font-size:clamp(1.5em,4.5vw,2.6em);font-weight:900;line-height:1.25;letter-spacing:.02em;margin-bottom:16px;position:relative;display:inline-block;padding:0 8px}
.brand-text{background:linear-gradient(135deg,#fbbf24 0%,#f97316 25%,#38bdf8 55%,#a78bfa 85%,#fbbf24 100%);background-size:200% 200%;-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;color:transparent;animation:shine 6s linear infinite;filter:drop-shadow(0 0 20px rgba(251,191,36,.35)) drop-shadow(0 0 40px rgba(56,189,248,.2));white-space:nowrap}
@keyframes shine{0%{background-position:0% 50%}100%{background-position:200% 50%}}
.brand::after{content:"";position:absolute;left:10%;right:10%;bottom:-10px;height:2px;background:linear-gradient(90deg,transparent,var(--gold),var(--accent),transparent);border-radius:2px;opacity:.6;animation:lineGlow 3s ease-in-out infinite}
@keyframes lineGlow{0%,100%{opacity:.3;transform:scaleX(.8)}50%{opacity:.8;transform:scaleX(1)}}
.subtitle{color:var(--muted);font-size:.95em;line-height:1.7;max-width:500px;margin:0 auto}
@keyframes fadeDown{from{opacity:0;transform:translateY(-16px)}to{opacity:1;transform:translateY(0)}}
.card{position:relative;background:var(--card-bg);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:20px;padding:22px;margin-bottom:16px;overflow:hidden;transition:transform .3s cubic-bezier(.22,.61,.36,1),border-color .3s ease,box-shadow .3s ease;animation:fadeUp .6s cubic-bezier(.22,.61,.36,1) both}
.card::before{content:"";position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(56,189,248,.6),transparent);opacity:0;transition:opacity .3s}
.card:hover{transform:translateY(-3px);border-color:rgba(56,189,248,.35);box-shadow:0 20px 50px -20px rgba(56,189,248,.25)}
.card:hover::before{opacity:1}
@keyframes fadeUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
.card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:14px}
.card-title{display:flex;flex-direction:column;gap:4px;min-width:0}
.name{font-size:1.1em;font-weight:700;color:#fff;letter-spacing:-.01em}
.location{font-size:.85em;color:var(--muted)}
.status-pill{flex-shrink:0;padding:4px 10px;font-size:.7em;font-weight:600;letter-spacing:.5px;color:var(--success);background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.3);border-radius:999px;text-transform:uppercase;display:flex;align-items:center;gap:5px}
.status-pill::before{content:"";width:5px;height:5px;border-radius:50%;background:var(--success);box-shadow:0 0 6px var(--success)}
.key-box{background:rgba(2,6,23,.75);border:1px solid rgba(148,163,184,.1);border-radius:12px;padding:12px 14px;font-family:'JetBrains Mono',ui-monospace,monospace;font-size:.75em;line-height:1.6;color:#cbd5e1;word-break:break-all;max-height:96px;overflow-y:auto}
.actions{display:flex;gap:10px;margin-top:14px}
.btn{flex:1;display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:11px 18px;border:none;border-radius:10px;font-family:inherit;font-size:.9em;font-weight:600;cursor:pointer;transition:all .2s cubic-bezier(.22,.61,.36,1);text-decoration:none}
.btn-primary{background:linear-gradient(135deg,#38bdf8,#0ea5e9);color:#04121f;box-shadow:0 4px 20px -4px rgba(56,189,248,.5)}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 8px 28px -4px rgba(56,189,248,.7)}
.btn-primary.copied{background:linear-gradient(135deg,#22c55e,#16a34a);color:#fff}
.btn-ghost{background:rgba(148,163,184,.08);color:var(--text);border:1px solid rgba(148,163,184,.15);flex:0 0 auto;padding:11px 16px}
.btn-ghost:hover{background:rgba(148,163,184,.15);border-color:rgba(148,163,184,.3)}
.btn-danger{background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.3)}
.btn-danger:hover{background:rgba(239,68,68,.3)}
.btn-warning{background:rgba(251,191,36,.15);color:#fcd34d;border:1px solid rgba(251,191,36,.3)}
.btn-warning:hover{background:rgba(251,191,36,.3)}
.qr-wrap{display:none;margin-top:16px;text-align:center;padding:20px;background:rgba(2,6,23,.6);border:1px dashed rgba(148,163,184,.2);border-radius:12px}
.qr-wrap.show{display:block;animation:fadeUp .3s ease both}
.qr-wrap canvas{background:#fff;padding:10px;border-radius:10px;display:inline-block}
.qr-caption{margin-top:12px;color:var(--muted);font-size:.8em}
.empty{text-align:center;padding:60px 20px;color:var(--muted);background:var(--card-bg);backdrop-filter:blur(20px);border:1px dashed var(--border);border-radius:20px}
footer{text-align:center;margin-top:56px;color:rgba(148,163,184,.5);font-size:.8em;letter-spacing:.5px}
footer .brand-mini{font-family:'Cinzel',serif;font-weight:700;color:var(--muted);letter-spacing:.05em}
footer .brand-mini span{background:linear-gradient(135deg,var(--gold),var(--accent));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.flash{padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:.9em}
.flash.success{background:rgba(34,197,94,.15);color:#86efac;border:1px solid rgba(34,197,94,.3)}
.flash.error{background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.3)}
@media(max-width:520px){.wrap{padding-top:40px}.brand{font-size:1.5em;line-height:1.35}.card{padding:18px;border-radius:16px}.btn{font-size:.85em;padding:10px 14px}}
"""

# ---------- Public page ----------
PUBLIC_TPL = """
<!DOCTYPE html><html lang="my"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>⚡ 𝕋𝕦𝕣𝕓𝕠 𝕋𝕦𝕟𝕟𝕖𝕝 𝕄𝕄</title>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&family=Cinzel:wght@700;900&display=swap" rel="stylesheet">
<style>{{ style|safe }}</style>
</head><body>
<div class="grid-bg"></div>
<div class="wrap">
<header>
  <div class="badge"><span class="dot"></span>All Systems Operational</div>
  <h1 class="brand"><span class="brand-text">⚡ 𝕋𝕦𝕣𝕓𝕠 𝕋𝕦𝕟𝕟𝕖𝕝 𝕄𝕄</span></h1>
  <p class="subtitle">Premium VLESS access · Fast &amp; Secure<br>Copy or scan QR to import into v2rayNG, NekoBox, or v2rayN.</p>
</header>
<div id="keys"></div>
<footer><div class="brand-mini">⚡ <span>𝕋𝕦𝕣𝕓𝕠 𝕋𝕦𝕟𝕟𝕖𝕝 𝕄𝕄</span></div><div style="margin-top:8px">VLESS · TLS · WebSocket</div></footer>
</div>
<script>
const KEYS = {{ keys|tojson }};
const c = document.getElementById("keys");
const esc = s => { const d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; };
if(!KEYS.length){ c.innerHTML='<div class="empty"><p>Key မရှိသေးပါ</p></div>'; }
KEYS.forEach((k,i)=>{
  const el=document.createElement("article"); el.className="card";
  el.innerHTML=`
    <div class="card-head">
      <div class="card-title">
        <div class="name">${esc(k.name)}</div>
        <div class="location">${esc(k.location)}</div>
      </div>
      <span class="status-pill">Online</span>
    </div>
    <div class="key-box">${esc(k.url)}</div>
    <div class="actions">
      <button class="btn btn-primary" data-copy="${i}"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg><span>Copy</span></button>
      <button class="btn btn-ghost" data-qr="${i}"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3h-3zM20 14h1M14 20h1M20 20h1"/></svg><span>QR</span></button>
    </div>
    <div class="qr-wrap" id="qr-${i}"></div>`;
  c.appendChild(el);
});
c.addEventListener("click", async e => {
  const cb=e.target.closest("[data-copy]"), qb=e.target.closest("[data-qr]");
  if(cb){
    const k=KEYS[cb.dataset.copy];
    try{ await navigator.clipboard.writeText(k.url);
      cb.classList.add("copied"); cb.querySelector("span").textContent="Copied!";
      setTimeout(()=>{cb.classList.remove("copied");cb.querySelector("span").textContent="Copy";},1800);
    }catch{alert("Copy failed");}
  }
  if(qb){
    const w=document.getElementById("qr-"+qb.dataset.qr);
    if(w.classList.contains("show")){w.classList.remove("show");return;}
    if(!w.hasChildNodes()){
      new QRCode(w,{text:KEYS[qb.dataset.qr].url,width:220,height:220,colorDark:"#0f172a",colorLight:"#ffffff",correctLevel:QRCode.CorrectLevel.M});
      const cap=document.createElement("div");cap.className="qr-caption";cap.textContent="Scan with your VPN app";w.appendChild(cap);
    }
    w.classList.add("show");
  }
});
</script></body></html>
"""

@app.route("/")
def index():
    rows = get_db().execute("SELECT name,location,url FROM keys WHERE active=1 ORDER BY id DESC").fetchall()
    return render_template_string(PUBLIC_TPL, style=BASE_STYLE, keys=[dict(r) for r in rows])

# ---------- Login ----------
LOGIN_TPL = """
<!DOCTYPE html><html lang="my"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Cinzel:wght@700;900&display=swap" rel="stylesheet">
<style>{{ style|safe }}
.login-box{max-width:380px;margin:80px auto 0;background:var(--card-bg);backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:20px;padding:32px;position:relative}
.login-box h1{font-family:'Cinzel',serif;font-size:1.4em;text-align:center;margin-bottom:24px;background:linear-gradient(135deg,var(--gold),var(--accent));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.login-box input{width:100%;padding:12px 14px;margin-bottom:12px;background:rgba(2,6,23,.75);border:1px solid var(--border);color:var(--text);border-radius:10px;font-size:.95em;font-family:inherit;transition:border-color .2s}
.login-box input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(56,189,248,.15)}
.login-box button{width:100%;padding:12px;background:linear-gradient(135deg,#38bdf8,#0ea5e9);color:#04121f;border:none;border-radius:10px;font-weight:700;cursor:pointer;font-size:1em;font-family:inherit;box-shadow:0 4px 20px -4px rgba(56,189,248,.5);transition:all .2s}
.login-box button:hover{transform:translateY(-1px);box-shadow:0 8px 28px -4px rgba(56,189,248,.7)}
</style></head><body>
<div class="grid-bg"></div>
<div class="login-box">
  <h1>Admin Login</h1>
  {% with msgs = get_flashed_messages(with_categories=true) %}{% for cat,m in msgs %}<div class="flash {{ cat }}">{{ m }}</div>{% endfor %}{% endwith %}
  <form method="post">
    <input type="hidden" name="_csrf" value="{{ session.csrf }}">
    <input name="username" placeholder="Username" required autocomplete="username">
    <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
    <button>Login</button>
  </form>
</div></body></html>
"""

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect(url_for("admin"))
    if request.method == "POST":
        check_csrf()
        if request.form.get("username") == ADMIN_USER and \
           check_password_hash(ADMIN_PASS_HASH, request.form.get("password", "")):
            session["user"] = ADMIN_USER
            return redirect(url_for("admin"))
        flash("Login မှားနေတယ်", "error")
    return render_template_string(LOGIN_TPL, style=BASE_STYLE)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- Admin ----------
ADMIN_TPL = """
<!DOCTYPE html><html lang="my"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin · 𝕋𝕦𝕣𝕓𝕠 𝕋𝕦𝕟𝕟𝕖𝕝 𝕄𝕄</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&family=Cinzel:wght@700;900&display=swap" rel="stylesheet">
<style>{{ style|safe }}
.admin-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px}
.admin-h h1{font-family:'Cinzel',serif;font-size:1.6em;background:linear-gradient(135deg,var(--gold),var(--accent));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.btn-sm{padding:7px 12px;font-size:.8em;flex:0 0 auto;display:inline-flex;align-items:center;gap:6px;border:none;border-radius:8px;font-weight:600;cursor:pointer;text-decoration:none;font-family:inherit;transition:all .2s}
.form-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.form-row input{flex:1;min-width:160px;padding:11px 14px;background:rgba(2,6,23,.75);border:1px solid var(--border);color:var(--text);border-radius:10px;font-size:.9em;font-family:inherit}
.form-row input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(56,189,248,.15)}
.klist{display:flex;flex-direction:column;gap:12px}
.krow{background:rgba(2,6,23,.5);border:1px solid var(--border);border-radius:12px;padding:16px}
.krow.inactive{opacity:.5}
.krow-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:10px;flex-wrap:wrap}
.krow-name{font-weight:700;color:#fff}
.krow-loc{font-size:.85em;color:var(--muted);margin-top:2px}
.krow-url{font-family:'JetBrains Mono',monospace;font-size:.72em;color:#cbd5e1;word-break:break-all;padding:8px 10px;background:rgba(0,0,0,.3);border-radius:6px;margin-bottom:10px;max-height:70px;overflow-y:auto}
.krow-actions{display:flex;gap:8px;flex-wrap:wrap}
.badge-state{padding:3px 8px;border-radius:6px;font-size:.7em;font-weight:700;text-transform:uppercase;letter-spacing:.5px}
.badge-state.on{background:rgba(34,197,94,.15);color:#86efac;border:1px solid rgba(34,197,94,.3)}
.badge-state.off{background:rgba(148,163,184,.15);color:var(--muted);border:1px solid rgba(148,163,184,.3)}
.edit-form{display:none;margin-top:10px;padding-top:12px;border-top:1px solid var(--border)}
.edit-form.show{display:block;animation:fadeUp .3s ease both}
</style></head><body>
<div class="grid-bg"></div>
<div class="wrap">
<div class="admin-h">
  <h1>⚙️ Admin Panel</h1>
  <div style="display:flex;gap:8px">
    <a href="{{ url_for('index') }}" class="btn-sm btn-ghost" target="_blank">View site ↗</a>
    <a href="{{ url_for('logout') }}" class="btn-sm btn-danger">Logout</a>
  </div>
</div>
{% with msgs = get_flashed_messages(with_categories=true) %}{% for cat,m in msgs %}<div class="flash {{ cat }}">{{ m }}</div>{% endfor %}{% endwith %}

<div class="card">
  <h3 style="color:#fff;margin-bottom:14px">➕ Add new key</h3>
  <form method="post" action="{{ url_for('admin_add') }}">
    <input type="hidden" name="_csrf" value="{{ session.csrf }}">
    <div class="form-row">
      <input name="name" placeholder="Name (e.g. SG-Prime)" required>
      <input name="location" placeholder="Location (e.g. 🇸🇬 Singapore)">
    </div>
    <div class="form-row">
      <input name="url" placeholder="vless://..." required style="font-family:'JetBrains Mono',monospace">
    </div>
    <button class="btn btn-primary" style="flex:0 0 auto;padding:11px 24px">Add key</button>
  </form>
</div>

<div class="card">
  <h3 style="color:#fff;margin-bottom:14px">🔑 Keys ({{ keys|length }})</h3>
  {% if not keys %}<p style="color:var(--muted);text-align:center;padding:20px">No keys yet</p>{% endif %}
  <div class="klist">
  {% for k in keys %}
    <div class="krow {% if not k.active %}inactive{% endif %}">
      <div class="krow-head">
        <div>
          <div class="krow-name">{{ k.name }}</div>
          <div class="krow-loc">{{ k.location }}</div>
        </div>
        <span class="badge-state {% if k.active %}on{% else %}off{% endif %}">{% if k.active %}active{% else %}hidden{% endif %}</span>
      </div>
      <div class="krow-url">{{ k.url }}</div>
      <div class="krow-actions">
        <button class="btn-sm btn-ghost" onclick="document.getElementById('edit-{{k.id}}').classList.toggle('show')">✏️ Edit</button>
        <form method="post" action="{{ url_for('admin_toggle', key_id=k.id) }}" style="display:inline">
          <input type="hidden" name="_csrf" value="{{ session.csrf }}">
          <button class="btn-sm btn-warning">{% if k.active %}🙈 Hide{% else %}👁 Show{% endif %}</button>
        </form>
        <form method="post" action="{{ url_for('admin_delete', key_id=k.id) }}" style="display:inline" onsubmit="return confirm('Delete {{ k.name }}?')">
          <input type="hidden" name="_csrf" value="{{ session.csrf }}">
          <button class="btn-sm btn-danger">🗑 Delete</button>
        </form>
      </div>
      <div class="edit-form" id="edit-{{k.id}}">
        <form method="post" action="{{ url_for('admin_edit', key_id=k.id) }}">
          <input type="hidden" name="_csrf" value="{{ session.csrf }}">
          <div class="form-row">
            <input name="name" value="{{ k.name }}" required>
            <input name="location" value="{{ k.location }}">
          </div>
          <div class="form-row">
            <input name="url" value="{{ k.url }}" required style="font-family:'JetBrains Mono',monospace">
          </div>
          <button class="btn-sm btn-primary" style="padding:8px 18px;border:none;border-radius:8px;font-weight:600;cursor:pointer;background:linear-gradient(135deg,#38bdf8,#0ea5e9);color:#04121f">💾 Save</button>
        </form>
      </div>
    </div>
  {% endfor %}
  </div>
</div>
</div></body></html>
"""

@app.route("/admin")
@login_required
def admin():
    rows = get_db().execute("SELECT * FROM keys ORDER BY id DESC").fetchall()
    return render_template_string(ADMIN_TPL, style=BASE_STYLE, keys=[dict(r) for r in rows])

@app.route("/admin/add", methods=["POST"])
@login_required
def admin_add():
    check_csrf()
    name = request.form.get("name", "").strip()
    location = request.form.get("location", "").strip()
    url = request.form.get("url", "").strip()
    if not (name and url):
        flash("Name နဲ့ URL ဖြည့်ပါ", "error")
        return redirect(url_for("admin"))
    db = get_db()
    db.execute("INSERT INTO keys (name, location, url) VALUES (?,?,?)", (name, location, url))
    db.commit()
    flash(f"'{name}' ထည့်ပြီးပါပြီ", "success")
    return redirect(url_for("admin"))

@app.route("/admin/edit/<int:key_id>", methods=["POST"])
@login_required
def admin_edit(key_id):
    check_csrf()
    name = request.form.get("name", "").strip()
    location = request.form.get("location", "").strip()
    url = request.form.get("url", "").strip()
    if not (name and url):
        flash("Name နဲ့ URL ဖြည့်ပါ", "error")
        return redirect(url_for("admin"))
    db = get_db()
    db.execute("UPDATE keys SET name=?,location=?,url=? WHERE id=?", (name, location, url, key_id))
    db.commit()
    flash("ပြင်ပြီးပါပြီ", "success")
    return redirect(url_for("admin"))

@app.route("/admin/toggle/<int:key_id>", methods=["POST"])
@login_required
def admin_toggle(key_id):
    check_csrf()
    db = get_db()
    db.execute("UPDATE keys SET active=1-active WHERE id=?", (key_id,))
    db.commit()
    return redirect(url_for("admin"))

@app.route("/admin/delete/<int:key_id>", methods=["POST"])
@login_required
def admin_delete(key_id):
    check_csrf()
    db = get_db()
    db.execute("DELETE FROM keys WHERE id=?", (key_id,))
    db.commit()
    flash("ဖျက်ပြီးပါပြီ", "success")
    return redirect(url_for("admin"))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
