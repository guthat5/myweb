import os
import re
import secrets
from datetime import timedelta
from functools import wraps
from zoneinfo import ZoneInfo

import psycopg
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.flask_client import OAuth
from flask import (
    Flask, abort, flash, g, redirect, render_template, request, session, url_for
)
from jinja2 import DictLoader
from psycopg.rows import dict_row
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Configuration (Vercel Environment Variables ကနေ ဖတ်ပါတယ်)
# ---------------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable မသတ်မှတ်ရသေးပါ")

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable မသတ်မှတ်ရသေးပါ")

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS_HASH = os.environ.get("ADMIN_PASS_HASH")
if not ADMIN_PASS_HASH:
    raise RuntimeError("ADMIN_PASS_HASH environment variable မသတ်မှတ်ရသေးပါ")

TELEGRAM_URL = "https://t.me/arsar2027"
MM_TZ = ZoneInfo("Asia/Yangon")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

ACTION_LABELS = {
    "login": "🔓 ဝင်ရောက်ခြင်း",
    "register": "🎉 အကောင့်ဖွင့်ခြင်း",
    "logout": "🚪 ထွက်ခြင်း",
    "copy": "📋 Key ကူးယူခြင်း",
    "qr": "📱 QR ကြည့်ခြင်း",
    "profile_update": "✏️ ပရိုဖိုင် ပြင်ခြင်း",
    "password_change": "🔑 Password ပြောင်းခြင်း",
}

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config.update(
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=14),
)

# ---------------------------------------------------------------------------
# Database helpers (Supabase / PostgreSQL, serverless-friendly)
# request တစ်ခုချင်းစီမှာ connection ဖွင့်ပြီး ပိတ်ပါတယ်
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def db_all(sql, params=()):
    return get_db().execute(sql, params).fetchall()


def db_one(sql, params=()):
    return get_db().execute(sql, params).fetchone()


def db_write(sql, params=(), returning=False):
    db = get_db()
    try:
        cur = db.execute(sql, params)
        row = cur.fetchone() if returning else None
        db.commit()
        return row
    except Exception:
        db.rollback()
        raise


_db_ready = False


def init_db():
    with psycopg.connect(DATABASE_URL) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                location TEXT DEFAULT '',
                url TEXT NOT NULL,
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMPTZ DEFAULT now()
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                name TEXT DEFAULT '',
                password_hash TEXT,
                google_id TEXT UNIQUE,
                created_at TIMESTAMPTZ DEFAULT now(),
                last_login TIMESTAMPTZ,
                login_count INTEGER DEFAULT 0
            )
        """)
        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ")
        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS login_count INTEGER DEFAULT 0")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS activity (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
                action TEXT NOT NULL,
                detail TEXT DEFAULT '',
                ip TEXT DEFAULT '',
                user_agent TEXT DEFAULT '',
                created_at TIMESTAMPTZ DEFAULT now()
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_user ON activity(user_id, id DESC)")
        conn.commit()


@app.before_request
def ensure_db_ready():
    # Serverless cold start တိုင်း table တွေ ရှိမရှိ တစ်ကြိမ်စစ်ပါတယ်
    global _db_ready
    if not _db_ready:
        init_db()
        _db_ready = True


# ---------------------------------------------------------------------------
# Security & session helpers
# ---------------------------------------------------------------------------
@app.before_request
def ensure_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)


def check_csrf():
    token = request.form.get("_csrf", "")
    if not secrets.compare_digest(token, session.get("csrf", "")):
        abort(400, "Invalid CSRF token")


def record_activity(uid, action, detail=""):
    ip = request.headers.get("X-Forwarded-For") or request.remote_addr or ""
    ip = ip.split(",")[0].strip()[:64]
    ua = (request.headers.get("User-Agent") or "")[:200]
    db_write(
        "INSERT INTO activity (user_id, action, detail, ip, user_agent) VALUES (%s,%s,%s,%s,%s)",
        (uid, action, detail[:200], ip, ua),
    )


def login_user(uid, action="login", method="email"):
    session.clear()
    session.permanent = True
    session["uid"] = uid
    db_write(
        "UPDATE users SET last_login=now(), login_count=login_count+1 WHERE id=%s", (uid,)
    )
    record_activity(uid, action, method)


def current_user():
    return db_one("""
        SELECT id, email, name,
               password_hash IS NOT NULL AS has_pw,
               google_id IS NOT NULL AS is_google,
               created_at, last_login, login_count
        FROM users WHERE id=%s
    """, (session.get("uid"),))


def user_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            return redirect(url_for("login"))
        g.me = current_user()
        if not g.me:
            session.clear()
            flash("Account ရှာမတွေ့ပါ၊ ပြန် login ဝင်ပါ", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper


def render_user(template, active, **ctx):
    return render_template(template, show_nav=True, active=active, me=g.me, **ctx)


@app.context_processor
def inject_globals():
    return {"telegram_url": TELEGRAM_URL}


@app.template_filter("mm")
def fmt_mm(dt):
    if not dt:
        return "—"
    return dt.astimezone(MM_TZ).strftime("%Y-%m-%d %H:%M")


# ---------------------------------------------------------------------------
# Google OAuth
# ---------------------------------------------------------------------------
oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
CSS = """
:root{--bg:#050816;--panel:rgba(15,23,42,.62);--line:rgba(148,163,184,.16);--text:#e2e8f0;
--muted:#94a3b8;--accent:#38bdf8;--gold:#fbbf24;--ok:#22c55e}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter','Noto Sans Myanmar',system-ui,sans-serif;background:var(--bg);color:var(--text);
min-height:100vh;line-height:1.6;padding:20px 16px 80px;overflow-x:hidden}
.bg{position:fixed;inset:0;z-index:-1;pointer-events:none;
background:radial-gradient(600px 400px at 0% 0%,rgba(56,189,248,.18),transparent 70%),
radial-gradient(600px 400px at 100% 100%,rgba(167,139,250,.18),transparent 70%)}
.wrap{max-width:1000px;margin:0 auto}
.nav{display:flex;flex-wrap:wrap;gap:6px;padding:10px;margin-bottom:24px;align-items:center}
.nav a{padding:9px 14px;border-radius:10px;color:var(--muted);text-decoration:none;font-size:.9em;font-weight:600;border:1px solid transparent;transition:all .2s}
.nav a:hover{color:var(--text);background:rgba(148,163,184,.08)}
.nav a.on{color:#04121f;background:linear-gradient(135deg,#38bdf8,#0ea5e9)}
.nav a.tg{color:#7dd3fc}
.nav .spacer{flex:1}
.nav .who{color:var(--muted);font-size:.85em;padding:0 8px}
.hero{text-align:center;margin:32px 0}
.brand{font-family:'Cinzel',serif;font-weight:900;font-size:clamp(1.6em,5vw,2.6em);margin:16px 0 10px;
background:linear-gradient(135deg,#fbbf24,#f97316,#38bdf8,#a78bfa);-webkit-background-clip:text;background-clip:text;color:transparent}
.brand-sm{font-family:'Cinzel',serif;font-weight:900;font-size:1.4em;margin-bottom:16px;
background:linear-gradient(135deg,var(--gold),var(--accent));-webkit-background-clip:text;background-clip:text;color:transparent}
.badge{display:inline-flex;align-items:center;gap:8px;padding:6px 14px;border:1px solid rgba(56,189,248,.3);
background:rgba(56,189,248,.1);border-radius:999px;font-size:.75em;font-weight:600;color:var(--accent);
letter-spacing:.08em;text-transform:uppercase}
.dot{width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 10px var(--ok)}
.muted{color:var(--muted)}.small{font-size:.82em}.center{text-align:center}
.mono{font-family:'JetBrains Mono',ui-monospace,monospace}
.card{background:var(--panel);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);
border:1px solid var(--line);border-radius:18px;padding:22px;margin-bottom:18px;animation:up .5s ease both}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px}
.key-card{display:flex;flex-direction:column;gap:12px;transition:transform .25s,border-color .25s,box-shadow .25s}
.key-card:hover{transform:translateY(-3px);border-color:rgba(56,189,248,.4);box-shadow:0 20px 50px -25px rgba(56,189,248,.4)}
.card-head{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}
.key-name{font-weight:700;color:#fff;font-size:1.05em}
.key-box{background:rgba(2,6,23,.75);border:1px solid var(--line);border-radius:10px;padding:10px 12px;
font-family:'JetBrains Mono',monospace;font-size:.72em;color:#cbd5e1;word-break:break-all;max-height:90px;overflow:auto}
.actions,.item-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:10px 16px;border-radius:10px;
border:1px solid transparent;font:inherit;font-weight:600;font-size:.9em;cursor:pointer;text-decoration:none;
color:var(--text);background:none;transition:all .2s}
.btn:hover{transform:translateY(-1px)}
.btn-primary{background:linear-gradient(135deg,#38bdf8,#0ea5e9);color:#04121f;box-shadow:0 6px 20px -6px rgba(56,189,248,.6)}
.btn-primary.copied{background:linear-gradient(135deg,#22c55e,#16a34a);color:#fff}
.btn-ghost{background:rgba(148,163,184,.08);border-color:var(--line)}
.btn-warning{background:rgba(251,191,36,.15);color:#fcd34d;border-color:rgba(251,191,36,.3)}
.btn-danger{background:rgba(239,68,68,.15);color:#fca5a5;border-color:rgba(239,68,68,.3)}
.btn-tg{background:linear-gradient(135deg,#229ED9,#1b7fb3);color:#fff;box-shadow:0 6px 20px -6px rgba(34,158,217,.6)}
.btn-sm{padding:7px 12px;font-size:.8em}
.btn.block{width:100%}
.google-btn{background:#fff;color:#1f1f1f;width:100%;margin-top:4px}
.google-btn:hover{background:#f1f5f9}
.pill{padding:3px 10px;border-radius:999px;font-size:.7em;font-weight:700;text-transform:uppercase;letter-spacing:.05em;border:1px solid}
.pill.ok{color:#86efac;background:rgba(34,197,94,.12);border-color:rgba(34,197,94,.3)}
.pill.off{color:var(--muted);background:rgba(148,163,184,.12);border-color:rgba(148,163,184,.3)}
.pill.gold{color:#fcd34d;background:rgba(251,191,36,.12);border-color:rgba(251,191,36,.3)}
.qr-wrap{display:none;text-align:center;padding:16px;background:rgba(2,6,23,.6);border:1px dashed var(--line);border-radius:12px}
.qr-wrap.show{display:block}
.qr-wrap canvas,.qr-wrap img{background:#fff;padding:8px;border-radius:8px}
.empty{text-align:center;color:var(--muted)}
.flash{padding:10px 14px;border-radius:10px;margin-bottom:14px;font-size:.9em;border:1px solid}
.flash.success{background:rgba(34,197,94,.15);color:#86efac;border-color:rgba(34,197,94,.3)}
.flash.error{background:rgba(239,68,68,.15);color:#fca5a5;border-color:rgba(239,68,68,.3)}
input{width:100%;padding:11px 14px;background:rgba(2,6,23,.75);border:1px solid var(--line);color:var(--text);
border-radius:10px;font:inherit;font-size:.95em;transition:border-color .2s,box-shadow .2s}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(56,189,248,.15)}
label{display:block;font-size:.8em;color:var(--muted);margin:12px 0 6px}
.auth-wrap{display:flex;justify-content:center;padding-top:40px}
.auth-box{width:100%;max-width:400px}
.auth-title{font-family:'Cinzel',serif;text-align:center;font-size:1.6em;
background:linear-gradient(135deg,var(--gold),var(--accent));-webkit-background-clip:text;background-clip:text;color:transparent}
.divider{display:flex;align-items:center;gap:12px;margin:18px 0;color:var(--muted);font-size:.8em}
.divider::before,.divider::after{content:"";flex:1;height:1px;background:var(--line)}
.switch{text-align:center;margin-top:18px;font-size:.85em;color:var(--muted)}
.switch a{color:var(--accent);text-decoration:none;font-weight:600}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:18px}
.stat{margin:0;text-align:center}
.stat-num{font-size:2em;font-weight:800;color:#fff}
.stat-num.ok{color:#86efac}.stat-num.gold{color:var(--gold)}
.section-head{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.section-title{font-size:1.1em;color:#fff;margin-bottom:14px}
.section-head .section-title{margin:0}
.search{max-width:260px}
.grid-form{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.grid-form .full{grid-column:1/-1}
.grid-form .btn{justify-self:start}
.item{border:1px solid var(--line);background:rgba(2,6,23,.45);border-radius:14px;padding:16px;margin-bottom:12px}
.item.dim{opacity:.55}
.item-head{display:flex;justify-content:space-between;gap:10px;margin-bottom:10px}
.item-title{font-weight:700;color:#fff}
.item-actions{margin-top:12px}
details.edit{width:100%}
details.edit summary{list-style:none;cursor:pointer;display:inline-flex}
details.edit summary::-webkit-details-marker{display:none}
details.edit .grid-form{margin-top:12px}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.9em}
th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--muted);font-weight:600;font-size:.78em;text-transform:uppercase;letter-spacing:.05em}
.avatar{width:72px;height:72px;border-radius:50%;margin:0 auto 12px;display:flex;align-items:center;
justify-content:center;font-size:1.8em;font-weight:800;color:#04121f;background:linear-gradient(135deg,var(--gold),var(--accent))}
.profile-head{text-align:center}
.kv{display:grid;grid-template-columns:auto 1fr;gap:10px 18px;font-size:.92em}
.kv dt{color:var(--muted)}
.kv dd{color:var(--text);word-break:break-all}
.recent{list-style:none}
.recent li{display:flex;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid var(--line);font-size:.9em;flex-wrap:wrap}
.recent li:last-child{border-bottom:none}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.contact-card{display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap}
footer{text-align:center;margin-top:48px;color:rgba(148,163,184,.5);font-size:.8em}
@keyframes up{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@media(max-width:600px){.grid-form,.two-col{grid-template-columns:1fr}.hero{margin:24px 0}.nav a{font-size:.82em;padding:8px 10px}}
"""

# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
BASE_TPL = """<!DOCTYPE html>
<html lang="my">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}Turbo Tunnel MM{% endblock %}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&family=Noto+Sans+Myanmar:wght@400;600;700&family=Cinzel:wght@700;900&display=swap" rel="stylesheet">
<style>""" + CSS + """</style>
</head>
<body>
<div class="bg"></div>
<div class="wrap">
  {% if show_nav %}
  <nav class="card nav">
    <a href="{{ url_for('index') }}" class="{{ 'on' if active == 'home' else '' }}">🔑 Keys</a>
    <a href="{{ url_for('profile') }}" class="{{ 'on' if active == 'profile' else '' }}">👤 Profile</a>
    <a href="{{ url_for('activity') }}" class="{{ 'on' if active == 'activity' else '' }}">📋 Activity</a>
    <a href="{{ telegram_url }}" target="_blank" rel="noopener" class="tg">✈️ Telegram</a>
    <span class="spacer"></span>
    <span class="who">{{ me.name or me.email }}</span>
    <a href="{{ url_for('logout') }}">🚪 Logout</a>
  </nav>
  {% endif %}

  {% with msgs = get_flashed_messages(with_categories=true) %}
    {% for cat, m in msgs %}<div class="flash {{ cat }}">{{ m }}</div>{% endfor %}
  {% endwith %}

  {% block content %}{% endblock %}
  <footer>⚡ Turbo Tunnel MM · VLESS · TLS · WebSocket</footer>
</div>
{% block scripts %}{% endblock %}
</body>
</html>
"""

AUTH_TPL = """{% extends "base.html" %}
{% block title %}{% if mode == 'register' %}အကောင့်ဖွင့်ရန်{% elif mode == 'admin' %}Admin Login{% else %}Login{% endif %} · Turbo Tunnel MM{% endblock %}
{% block content %}
<div class="auth-wrap">
  <div class="card auth-box">
    <h1 class="auth-title">
      {% if mode == 'register' %}Create Account{% elif mode == 'admin' %}Admin Login{% else %}Welcome Back{% endif %}
    </h1>
    <p class="muted center small" style="margin:6px 0 20px">
      {% if mode == 'register' %}အကောင့်ဖွင့်ပြီး VPN key တွေကို ယူပါ
      {% elif mode == 'admin' %}Admin panel ထဲ ဝင်ရန်
      {% else %}အကောင့်ထဲ ဝင်ပြီး VPN key တွေကို ယူပါ{% endif %}
    </p>

    {% if mode != 'admin' %}
      <a class="btn google-btn" href="{{ url_for('google_login') }}">
        <b style="color:#4285f4">G</b> Google နဲ့ ဆက်လုပ်မယ်
      </a>
      <div class="divider">သို့မဟုတ်</div>
    {% endif %}

    <form method="post">
      <input type="hidden" name="_csrf" value="{{ session.csrf }}">
      {% if mode == 'register' %}
        <label for="name">နာမည်</label>
        <input id="name" name="name" placeholder="သင့်နာမည်" autocomplete="name" maxlength="60">
      {% endif %}
      {% if mode == 'admin' %}
        <label for="username">Username</label>
        <input id="username" name="username" required autocomplete="username">
      {% else %}
        <label for="email">Email</label>
        <input id="email" type="email" name="email" placeholder="you@example.com" required autocomplete="email">
      {% endif %}
      <label for="password">Password{% if mode == 'register' %} (အနည်းဆုံး ၈ လုံး){% endif %}</label>
      <input id="password" type="password" name="password" placeholder="••••••••" required
             {% if mode == 'register' %}minlength="8" autocomplete="new-password"{% else %}autocomplete="current-password"{% endif %}>
      <div style="height:18px"></div>
      <button class="btn btn-primary block" type="submit">
        {% if mode == 'register' %}အကောင့်ဖွင့်မယ်{% else %}Login ဝင်မယ်{% endif %}
      </button>
    </form>

    {% if mode == 'login' %}
      <p class="switch">အကောင့်မရှိသေးဘူးလား? <a href="{{ url_for('register') }}">အကောင့်ဖွင့်ပါ</a></p>
    {% elif mode == 'register' %}
      <p class="switch">အကောင့်ရှိပြီးသားလား? <a href="{{ url_for('login') }}">Login ဝင်ပါ</a></p>
    {% endif %}
  </div>
</div>
{% endblock %}
"""

KEYS_TPL = """{% extends "base.html" %}
{% block title %}VPN Keys · Turbo Tunnel MM{% endblock %}
{% block content %}
<section class="hero">
  <span class="badge"><span class="dot"></span>All Systems Operational</span>
  <h1 class="brand">Turbo Tunnel MM</h1>
  <p class="muted">Premium VLESS access · v2rayNG, NekoBox, v2rayN မှာ copy သို့မဟုတ် QR scan ဖတ်ပြီး import လုပ်ပါ</p>
</section>

{% if keys %}
<div class="grid" id="keys">
  {% for k in keys %}
  <article class="card key-card">
    <div class="card-head">
      <div>
        <div class="key-name">{{ k.name }}</div>
        <div class="muted small">{{ k.location }}</div>
      </div>
      <span class="pill ok">Online</span>
    </div>
    <div class="key-box">{{ k.url }}</div>
    <div class="actions">
      <button class="btn btn-primary" data-copy="{{ loop.index0 }}">Copy</button>
      <button class="btn btn-ghost" data-qr="{{ loop.index0 }}">QR</button>
    </div>
    <div class="qr-wrap" id="qr-{{ loop.index0 }}"></div>
  </article>
  {% endfor %}
</div>
{% else %}
<div class="card empty"><p>Key မရှိသေးပါ။ Admin က ထည့်ပြီးမှ ပြန်ကြည့်ပါ။</p></div>
{% endif %}

<div class="card contact-card" style="margin-top:24px">
  <div>
    <b>အကူအညီ လိုအပ်ရင်</b>
    <div class="muted small">Telegram channel မှာ ဆက်သွယ်နိုင်ပါတယ်</div>
  </div>
  <a class="btn btn-tg" href="{{ telegram_url }}" target="_blank" rel="noopener">✈️ Telegram Channel</a>
</div>
{% endblock %}

{% block scripts %}
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
<script>
const KEYS = {{ keys|tojson }};
const CSRF = {{ session.csrf|tojson }};
const LOG_URL = "{{ url_for('activity_log') }}";

function logAction(action, key) {
  fetch(LOG_URL, {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-CSRF-Token": CSRF},
    body: JSON.stringify({action: action, key_id: key.id}),
    keepalive: true
  }).catch(() => {});
}

const list = document.getElementById("keys");
if (list) {
  list.addEventListener("click", async (e) => {
    const copyBtn = e.target.closest("[data-copy]");
    const qrBtn = e.target.closest("[data-qr]");

    if (copyBtn) {
      const key = KEYS[copyBtn.dataset.copy];
      try {
        await navigator.clipboard.writeText(key.url);
        copyBtn.textContent = "Copied!";
        copyBtn.classList.add("copied");
        setTimeout(() => {
          copyBtn.textContent = "Copy";
          copyBtn.classList.remove("copied");
        }, 1600);
        logAction("copy", key);
      } catch {
        alert("Copy မရပါ");
      }
    }

    if (qrBtn) {
      const idx = qrBtn.dataset.qr;
      const box = document.getElementById("qr-" + idx);
      const visible = box.classList.toggle("show");
      if (visible) {
        if (!box.hasChildNodes()) {
          new QRCode(box, {
            text: KEYS[idx].url,
            width: 200,
            height: 200,
            colorDark: "#0f172a",
            colorLight: "#ffffff",
            correctLevel: QRCode.CorrectLevel.M
          });
        }
        logAction("qr", KEYS[idx]);
      }
    }
  });
}
</script>
{% endblock %}
"""

PROFILE_TPL = """{% extends "base.html" %}
{% block title %}Profile · Turbo Tunnel MM{% endblock %}
{% block content %}
<section class="card profile-head">
  <div class="avatar">{{ (me.name or me.email)[:1]|upper }}</div>
  <h2 class="section-title" style="margin:0">{{ me.name or 'နာမည် မသတ်မှတ်ရသေးပါ' }}</h2>
  <p class="muted small">{{ me.email }}</p>
  <div style="margin-top:10px;display:flex;gap:8px;justify-content:center;flex-wrap:wrap">
    {% if me.is_google %}<span class="pill gold">Google</span>{% endif %}
    {% if me.has_pw %}<span class="pill off">Email + Password</span>{% endif %}
  </div>
</section>

<section class="stats">
  <div class="card stat"><div class="stat-num ok">{{ stats.copies or 0 }}</div><div class="muted small">Key ကူးယူခဲ့မှု</div></div>
  <div class="card stat"><div class="stat-num">{{ stats.qrs or 0 }}</div><div class="muted small">QR ကြည့်ခဲ့မှု</div></div>
  <div class="card stat"><div class="stat-num gold">{{ me.login_count or 0 }}</div><div class="muted small">Login အကြိမ်</div></div>
  <div class="card stat"><div class="stat-num">{{ stats.total or 0 }}</div><div class="muted small">စုစုပေါင်း လှုပ်ရှားမှု</div></div>
</section>

<div class="two-col">
  <section class="card">
    <h2 class="section-title">📄 အကောင့်အချက်အလက်</h2>
    <dl class="kv">
      <dt>Email</dt><dd class="mono">{{ me.email }}</dd>
      <dt>နာမည်</dt><dd>{{ me.name or '—' }}</dd>
      <dt>အကောင့်ဖွင့်သည့်နေ့</dt><dd>{{ me.created_at|mm }}</dd>
      <dt>နောက်ဆုံး Login</dt><dd>{{ me.last_login|mm }}</dd>
      <dt>Login နည်းလမ်း</dt>
      <dd>{% if me.is_google %}Google{% endif %}{% if me.is_google and me.has_pw %} · {% endif %}{% if me.has_pw %}Email{% endif %}</dd>
    </dl>
  </section>

  <section class="card">
    <h2 class="section-title">✏️ ပရိုဖိုင် ပြင်ရန်</h2>
    <form method="post" action="{{ url_for('profile_update') }}">
      <input type="hidden" name="_csrf" value="{{ session.csrf }}">
      <label for="name">နာမည်</label>
      <input id="name" name="name" value="{{ me.name or '' }}" maxlength="60" placeholder="သင့်နာမည်">
      <div style="height:14px"></div>
      <button class="btn btn-primary block" type="submit">💾 သိမ်းမယ်</button>
    </form>
  </section>
</div>

<section class="card">
  <h2 class="section-title">🔑 Password {% if me.has_pw %}ပြောင်းရန်{% else %}သတ်မှတ်ရန်{% endif %}</h2>
  {% if not me.has_pw %}
    <p class="muted small" style="margin-bottom:6px">Google နဲ့ပဲ ဝင်ထားတာဆိုရင် password သတ်မှတ်ထားမှ Email နဲ့လည်း ဝင်လို့ရမှာပါ။</p>
  {% endif %}
  <form method="post" action="{{ url_for('profile_password') }}">
    <input type="hidden" name="_csrf" value="{{ session.csrf }}">
    {% if me.has_pw %}
      <label for="current">လက်ရှိ password</label>
      <input id="current" type="password" name="current" required autocomplete="current-password">
    {% endif %}
    <label for="new">Password အသစ် (အနည်းဆုံး ၈ လုံး)</label>
    <input id="new" type="password" name="new" minlength="8" required autocomplete="new-password">
    <div style="height:14px"></div>
    <button class="btn btn-warning" type="submit">🔐 ပြောင်းမယ်</button>
  </form>
</section>

<section class="card">
  <div class="section-head">
    <h2 class="section-title">🕘 နောက်ဆုံး လှုပ်ရှားမှု ၁၀ ခု</h2>
    <a class="btn btn-ghost btn-sm" href="{{ url_for('activity') }}">အားလုံးကြည့်မယ် →</a>
  </div>
  <ul class="recent">
    {% for r in recent %}
      <li>
        <span>{{ labels.get(r.action, r.action) }}{% if r.detail %} · <span class="muted">{{ r.detail }}</span>{% endif %}</span>
        <span class="muted small">{{ r.created_at|mm }}</span>
      </li>
    {% else %}
      <li class="muted">လှုပ်ရှားမှု မရှိသေးပါ</li>
    {% endfor %}
  </ul>
</section>
{% endblock %}
"""

ACTIVITY_TPL = """{% extends "base.html" %}
{% block title %}Activity · Turbo Tunnel MM{% endblock %}
{% block content %}
<section class="card">
  <div class="section-head">
    <h2 class="section-title">📋 လှုပ်ရှားမှု မှတ်တမ်း</h2>
    <span class="muted small">နောက်ဆုံး ၂၀၀ ကြောင်း</span>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>အချိန် (MM)</th><th>လုပ်ဆောင်ချက်</th><th>အသေးစိတ်</th><th>IP</th><th>Device</th></tr>
      </thead>
      <tbody>
        {% for r in rows %}
        <tr>
          <td class="muted small" style="white-space:nowrap">{{ r.created_at|mm }}</td>
          <td>{{ labels.get(r.action, r.action) }}</td>
          <td>{{ r.detail or '—' }}</td>
          <td class="mono small">{{ r.ip or '—' }}</td>
          <td class="muted small">{{ (r.user_agent or '—')[:60] }}</td>
        </tr>
        {% else %}
        <tr><td colspan="5" class="muted center">လှုပ်ရှားမှု မရှိသေးပါ</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</section>
{% endblock %}
"""

ADMIN_TPL = """{% extends "base.html" %}
{% block title %}Admin · Turbo Tunnel MM{% endblock %}
{% block content %}
<header style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:24px">
  <div class="brand-sm">⚙️ Admin Panel</div>
  <nav style="display:flex;gap:8px">
    <a class="btn btn-ghost btn-sm" href="{{ url_for('index') }}" target="_blank">View site ↗</a>
    <a class="btn btn-danger btn-sm" href="{{ url_for('admin_logout') }}">Logout</a>
  </nav>
</header>

<section class="stats">
  <div class="card stat"><div class="stat-num">{{ stats.keys }}</div><div class="muted small">စုစုပေါင်း Keys</div></div>
  <div class="card stat"><div class="stat-num ok">{{ stats.active }}</div><div class="muted small">Active Keys</div></div>
  <div class="card stat"><div class="stat-num">{{ stats.users }}</div><div class="muted small">Users</div></div>
  <div class="card stat"><div class="stat-num gold">{{ stats.google }}</div><div class="muted small">Google Users</div></div>
</section>

<section class="card">
  <h2 class="section-title">➕ Key အသစ် ထည့်ရန်</h2>
  <form method="post" action="{{ url_for('admin_add') }}" class="grid-form">
    <input type="hidden" name="_csrf" value="{{ session.csrf }}">
    <input name="name" placeholder="Name (ဥပမာ SG-Prime)" required>
    <input name="location" placeholder="Location (ဥပမာ 🇸🇬 Singapore)">
    <input name="url" class="mono full" placeholder="vless://..." required>
    <button class="btn btn-primary" type="submit">Key ထည့်မယ်</button>
  </form>
</section>

<section class="card">
  <div class="section-head">
    <h2 class="section-title">🔑 Keys ({{ keys|length }})</h2>
    <input id="search" class="search" placeholder="🔍 ရှာရန်...">
  </div>

  {% for k in keys %}
  <div class="item key-item {% if not k.active %}dim{% endif %}"
       data-search="{{ (k.name ~ ' ' ~ (k.location or ''))|lower }}">
    <div class="item-head">
      <div>
        <div class="item-title">{{ k.name }}</div>
        <div class="muted small">{{ k.location or '—' }}</div>
      </div>
      <span class="pill {{ 'ok' if k.active else 'off' }}">{{ 'active' if k.active else 'hidden' }}</span>
    </div>
    <div class="key-box">{{ k.url }}</div>

    <div class="item-actions">
      <details class="edit">
        <summary class="btn btn-ghost btn-sm">✏️ Edit</summary>
        <form method="post" action="{{ url_for('admin_edit', key_id=k.id) }}" class="grid-form">
          <input type="hidden" name="_csrf" value="{{ session.csrf }}">
          <input name="name" value="{{ k.name }}" required>
          <input name="location" value="{{ k.location or '' }}">
          <input name="url" class="mono full" value="{{ k.url }}" required>
          <button class="btn btn-primary btn-sm" type="submit">💾 Save</button>
        </form>
      </details>

      <form method="post" action="{{ url_for('admin_toggle', key_id=k.id) }}">
        <input type="hidden" name="_csrf" value="{{ session.csrf }}">
        <button class="btn btn-warning btn-sm" type="submit">{{ '🙈 Hide' if k.active else '👁 Show' }}</button>
      </form>

      <form method="post" action="{{ url_for('admin_delete', key_id=k.id) }}"
            onsubmit="return confirm('ဒီ key ကို ဖျက်မလား?')">
        <input type="hidden" name="_csrf" value="{{ session.csrf }}">
        <button class="btn btn-danger btn-sm" type="submit">🗑 Delete</button>
      </form>
    </div>
  </div>
  {% else %}
    <p class="muted center">Key မရှိသေးပါ</p>
  {% endfor %}
</section>

<section class="card">
  <h2 class="section-title">👥 Users ({{ users|length }})</h2>
  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>Email</th><th>နာမည်</th><th>Login နည်း</th><th>Login အကြိမ်</th><th>နောက်ဆုံး Login</th><th></th></tr>
      </thead>
      <tbody>
        {% for u in users %}
        <tr>
          <td class="mono small">{{ u.email }}</td>
          <td>{{ u.name or '—' }}</td>
          <td>
            {% if u.is_google %}<span class="pill gold">Google</span>{% endif %}
            {% if u.has_pw %}<span class="pill off">Email</span>{% endif %}
          </td>
          <td class="small">{{ u.login_count or 0 }}</td>
          <td class="muted small">{{ u.last_login|mm }}</td>
          <td>
            <form method="post" action="{{ url_for('admin_user_delete', user_id=u.id) }}"
                  onsubmit="return confirm('ဒီ user ကို ဖျက်မလား?')">
              <input type="hidden" name="_csrf" value="{{ session.csrf }}">
              <button class="btn btn-danger btn-sm" type="submit">ဖျက်</button>
            </form>
          </td>
        </tr>
        {% else %}
        <tr><td colspan="6" class="muted center">User မရှိသေးပါ</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</section>
{% endblock %}

{% block scripts %}
<script>
const search = document.getElementById("search");
search.addEventListener("input", () => {
  const q = search.value.trim().toLowerCase();
  document.querySelectorAll(".key-item").forEach(el => {
    el.style.display = el.dataset.search.includes(q) ? "" : "none";
  });
});
</script>
{% endblock %}
"""

app.jinja_loader = DictLoader({
    "base.html": BASE_TPL,
    "auth.html": AUTH_TPL,
    "keys.html": KEYS_TPL,
    "profile.html": PROFILE_TPL,
    "activity.html": ACTIVITY_TPL,
    "admin.html": ADMIN_TPL,
})

# ---------------------------------------------------------------------------
# User routes
# ---------------------------------------------------------------------------
@app.route("/")
@user_required
def index():
    keys = db_all("SELECT id, name, location, url FROM keys WHERE active=TRUE ORDER BY id DESC")
    return render_user("keys.html", "home", keys=keys)


@app.route("/profile")
@user_required
def profile():
    stats = db_one("""
        SELECT COUNT(*) FILTER (WHERE action='copy') AS copies,
               COUNT(*) FILTER (WHERE action='qr')   AS qrs,
               COUNT(*) AS total
        FROM activity WHERE user_id=%s
    """, (g.me["id"],))
    recent = db_all(
        "SELECT action, detail, created_at FROM activity WHERE user_id=%s ORDER BY id DESC LIMIT 10",
        (g.me["id"],),
    )
    return render_user("profile.html", "profile", stats=stats, recent=recent, labels=ACTION_LABELS)


@app.route("/profile/update", methods=["POST"])
@user_required
def profile_update():
    check_csrf()
    name = request.form.get("name", "").strip()[:60]
    db_write("UPDATE users SET name=%s WHERE id=%s", (name, g.me["id"]))
    record_activity(g.me["id"], "profile_update", name or "(နာမည် ဖျက်)")
    flash("ပရိုဖိုင် ပြင်ပြီးပါပြီ", "success")
    return redirect(url_for("profile"))


@app.route("/profile/password", methods=["POST"])
@user_required
def profile_password():
    check_csrf()
    current = request.form.get("current", "")
    new = request.form.get("new", "")
    if len(new) < 8:
        flash("Password အနည်းဆုံး ၈ လုံး ရှိရပါမယ်", "error")
        return redirect(url_for("profile"))

    row = db_one("SELECT password_hash FROM users WHERE id=%s", (g.me["id"],))
    if row["password_hash"] and not check_password_hash(row["password_hash"], current):
        flash("လက်ရှိ password မှားနေတယ်", "error")
        return redirect(url_for("profile"))

    db_write("UPDATE users SET password_hash=%s WHERE id=%s",
             (generate_password_hash(new), g.me["id"]))
    record_activity(g.me["id"], "password_change")
    flash("Password ပြောင်းပြီးပါပြီ", "success")
    return redirect(url_for("profile"))


@app.route("/activity")
@user_required
def activity():
    rows = db_all("""
        SELECT action, detail, ip, user_agent, created_at
        FROM activity WHERE user_id=%s ORDER BY id DESC LIMIT 200
    """, (g.me["id"],))
    return render_user("activity.html", "activity", rows=rows, labels=ACTION_LABELS)


@app.route("/activity/log", methods=["POST"])
@user_required
def activity_log():
    token = request.headers.get("X-CSRF-Token", "")
    if not secrets.compare_digest(token, session.get("csrf", "")):
        abort(400)
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    key_id = data.get("key_id")
    if action not in ("copy", "qr") or not isinstance(key_id, int):
        abort(400)
    key = db_one("SELECT name FROM keys WHERE id=%s AND active=TRUE", (key_id,))
    if not key:
        abort(404)
    record_activity(g.me["id"], action, key["name"])
    return {"ok": True}


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("uid"):
        return redirect(url_for("index"))

    if request.method == "POST":
        check_csrf()
        email = request.form.get("email", "").strip().lower()
        name = request.form.get("name", "").strip()[:60]
        password = request.form.get("password", "")

        if not EMAIL_RE.match(email):
            flash("Email မှန်မှန်ရိုက်ပါ", "error")
        elif len(password) < 8:
            flash("Password အနည်းဆုံး ၈ လုံး ရှိရပါမယ်", "error")
        else:
            try:
                row = db_write(
                    "INSERT INTO users (email, name, password_hash) VALUES (%s,%s,%s) RETURNING id",
                    (email, name, generate_password_hash(password)),
                    returning=True,
                )
            except psycopg.errors.UniqueViolation:
                flash("ဒီ email နဲ့ account ရှိပြီးသားပါ", "error")
                return redirect(url_for("register"))
            login_user(row["id"], action="register", method="email")
            flash("အကောင့်ဖွင့်ပြီးပါပြီ 🎉", "success")
            return redirect(url_for("index"))

    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("uid"):
        return redirect(url_for("index"))

    if request.method == "POST":
        check_csrf()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        row = db_one("SELECT id, password_hash FROM users WHERE email=%s", (email,))
        if row and row["password_hash"] and check_password_hash(row["password_hash"], password):
            login_user(row["id"], action="login", method="email")
            return redirect(url_for("index"))
        flash("Email သို့မဟုတ် password မှားနေတယ်", "error")

    return render_template("auth.html", mode="login")


@app.route("/logout")
def logout():
    uid = session.get("uid")
    if uid:
        record_activity(uid, "logout")
    session.pop("uid", None)
    return redirect(url_for("login"))


@app.route("/auth/google")
def google_login():
    return google.authorize_redirect(url_for("google_callback", _external=True))


@app.route("/auth/google/callback")
def google_callback():
    try:
        token = google.authorize_access_token()
    except OAuthError:
        flash("Google login ပယ်ဖျက်ခံရပါတယ်", "error")
        return redirect(url_for("login"))

    info = token.get("userinfo") or google.userinfo(token=token)
    if not info.get("email_verified"):
        flash("Google email မအတည်ပြုရသေးပါ", "error")
        return redirect(url_for("login"))

    email = info["email"].lower()
    google_id = info["sub"]
    name = (info.get("name") or "")[:60]

    row = db_one("SELECT id, google_id FROM users WHERE google_id=%s OR email=%s", (google_id, email))
    if row:
        user_id = row["id"]
        action = "login"
        if not row["google_id"]:
            db_write("UPDATE users SET google_id=%s WHERE id=%s", (google_id, user_id))
    else:
        row = db_write(
            "INSERT INTO users (email, name, google_id) VALUES (%s,%s,%s) RETURNING id",
            (email, name, google_id),
            returning=True,
        )
        user_id = row["id"]
        action = "register"

    login_user(user_id, action=action, method="google")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("is_admin"):
        return redirect(url_for("admin"))

    if request.method == "POST":
        check_csrf()
        if (request.form.get("username") == ADMIN_USER and
                check_password_hash(ADMIN_PASS_HASH, request.form.get("password", ""))):
            session["is_admin"] = True
            return redirect(url_for("admin"))
        flash("Username သို့မဟုတ် password မှားနေတယ်", "error")

    return render_template("auth.html", mode="admin")


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


@app.route("/admin")
@admin_required
def admin():
    keys = db_all("SELECT * FROM keys ORDER BY id DESC")
    users = db_all("""
        SELECT id, email, name,
               google_id IS NOT NULL AS is_google,
               password_hash IS NOT NULL AS has_pw,
               login_count, last_login, created_at
        FROM users ORDER BY id DESC
    """)
    stats = {
        "keys": len(keys),
        "active": sum(1 for k in keys if k["active"]),
        "users": len(users),
        "google": sum(1 for u in users if u["is_google"]),
    }
    return render_template("admin.html", keys=keys, users=users, stats=stats)


def read_key_form():
    name = request.form.get("name", "").strip()
    location = request.form.get("location", "").strip()
    url = request.form.get("url", "").strip()
    if not name or not url:
        flash("Name နဲ့ URL ဖြည့်ပါ", "error")
        return None
    if not url.startswith("vless://"):
        flash("URL သည် vless:// နဲ့ စရပါမယ်", "error")
        return None
    return name, location, url


@app.route("/admin/keys/add", methods=["POST"])
@admin_required
def admin_add():
    check_csrf()
    data = read_key_form()
    if data:
        db_write("INSERT INTO keys (name, location, url) VALUES (%s,%s,%s)", data)
        flash(f"'{data[0]}' ထည့်ပြီးပါပြီ", "success")
    return redirect(url_for("admin"))


@app.route("/admin/keys/<int:key_id>/edit", methods=["POST"])
@admin_required
def admin_edit(key_id):
    check_csrf()
    data = read_key_form()
    if data:
        db_write("UPDATE keys SET name=%s, location=%s, url=%s WHERE id=%s", data + (key_id,))
        flash("ပြင်ပြီးပါပြီ", "success")
    return redirect(url_for("admin"))


@app.route("/admin/keys/<int:key_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle(key_id):
    check_csrf()
    db_write("UPDATE keys SET active = NOT active WHERE id=%s", (key_id,))
    return redirect(url_for("admin"))


@app.route("/admin/keys/<int:key_id>/delete", methods=["POST"])
@admin_required
def admin_delete(key_id):
    check_csrf()
    db_write("DELETE FROM keys WHERE id=%s", (key_id,))
    flash("ဖျက်ပြီးပါပြီ", "success")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_user_delete(user_id):
    check_csrf()
    db_write("DELETE FROM users WHERE id=%s", (user_id,))
    flash("User ဖျက်ပြီးပါပြီ", "success")
    return redirect(url_for("admin"))


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
