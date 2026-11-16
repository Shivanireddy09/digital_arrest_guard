# -*- coding: utf-8 -*-
import hashlib
import re
import secrets
import sqlite3
import sys
import time
from datetime import datetime, timedelta

from flask import Flask, g, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from scam_engine import analyze
from lang_pack import ADVICE, CAT, LANGS, LOW_ADVICE, SAMPLES, TIPS, UI, WHY

guard_app = Flask(__name__)
guard_app.secret_key = "change-this-to-a-long-random-string"
guard_app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # set True when served over HTTPS
    MAX_CONTENT_LENGTH=64 * 1024,  # reject huge requests
)

DB = "guard.db"
MAX_FAILS, LOCK_MINUTES = 5, 15
RATE = {}  # ip -> list of timestamps (simple in-memory rate limiter)


# ------------------------------------------------------------ database
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@guard_app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    con = sqlite3.connect(DB)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
        failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT);
    CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, username TEXT, ip TEXT, event TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, username TEXT, sha256 TEXT,
        preview TEXT, score INTEGER, level TEXT, lang TEXT);
    CREATE TABLE IF NOT EXISTS reports(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, username TEXT, preview TEXT, level TEXT);
    """)
    con.commit()
    con.close()


def now():
    return datetime.utcnow().isoformat(timespec="seconds")


def log(event, username=None):
    db().execute("INSERT INTO audit_log(ts, username, ip, event) VALUES (?,?,?,?)",
                 (now(), username, request.remote_addr, event))
    db().commit()


# ------------------------------------------------------------ security
@guard_app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'"
    return resp


@guard_app.before_request
def csrf_and_rate_limit():
    if request.method == "POST":
        # CSRF check
        if not session.get("csrf") or request.form.get("csrf") != session.get("csrf"):
            log("CSRF_BLOCKED", session.get("user"))
            return render_page("<p class='err'>{{ t.csrf }}</p>"), 400
        # rate limit: 30 POSTs / minute / IP
        ip, t0 = request.remote_addr, time.time()
        RATE[ip] = [x for x in RATE.get(ip, []) if t0 - x < 60] + [t0]
        if len(RATE[ip]) > 30:
            log("RATE_LIMITED", session.get("user"))
            return render_page("<p class='err'>{{ t.toomany }}</p>"), 429


def strong_password(p):
    return (len(p) >= 8 and re.search(r"[A-Z]", p) and re.search(r"[a-z]", p)
            and re.search(r"\d", p) and re.search(r"[^\w\s]", p))


def lang():
    return session.get("lang", "en")


# ------------------------------------------------------------ templates
BASE = """<!doctype html>
<html lang="{{ lg }}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ t.title }}</title>
<style>
 body{font-family:'Noto Sans','Noto Sans Devanagari','Noto Sans Telugu','Nirmala UI','Segoe UI',Arial,sans-serif;
      margin:0;background:#f4f6f8;color:#1b2430}
 header{background:#12355b;color:#fff;padding:14px 20px;display:flex;flex-wrap:wrap;gap:10px;justify-content:space-between;align-items:center}
 header a{color:#cfe3ff;margin-left:12px;text-decoration:none}
 main{max-width:860px;margin:20px auto;padding:0 16px}
 .card{background:#fff;border-radius:10px;padding:18px;margin-bottom:16px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
 textarea{width:100%;min-height:150px;padding:10px;font-size:16px;box-sizing:border-box}
 input[type=text],input[type=password]{width:100%;padding:10px;font-size:16px;box-sizing:border-box;margin:6px 0 14px}
 button{background:#12355b;color:#fff;border:0;padding:10px 18px;border-radius:6px;font-size:16px;cursor:pointer}
 .meter{height:18px;background:#e3e8ee;border-radius:9px;overflow:hidden}
 .bar{height:100%}
 .HIGH{background:#c62828}.MEDIUM{background:#ef8f00}.LOW{background:#2e7d32}
 .badge{display:inline-block;color:#fff;padding:4px 12px;border-radius:14px;font-weight:bold}
 .err{color:#c62828;font-weight:bold}.ok{color:#2e7d32;font-weight:bold}
 .chip{display:inline-block;background:#eef2f7;border-radius:10px;padding:2px 8px;margin:2px;font-size:13px}
 table{width:100%;border-collapse:collapse;font-size:14px}td,th{border-bottom:1px solid #e3e8ee;padding:6px;text-align:left}
 .help{background:#fff4e5;border-left:5px solid #ef8f00}
</style></head><body>
<header><b>{{ t.title }}</b>
<span>{% for c,n in langs.items() %}<a href="/lang/{{ c }}">{{ n }}</a>{% endfor %}
{% if user %}<a href="/">{{ user }}</a>{% if role=='admin' %}<a href="/admin">{{ t.admin }}</a>{% endif %}<a href="/logout">{{ t.logout }}</a>{% endif %}</span></header>
<main>{{ body|safe }}<div class="card help">{{ t.helpline }}</div></main></body></html>"""


def render_page(body_tpl, **ctx):
    lg = lang()
    base_ctx = dict(t=type("T", (), UI[lg]), lg=lg, langs=LANGS, user=session.get("user"),
                    role=session.get("role"), csrf=csrf_token())
    base_ctx.update(ctx)
    body = render_template_string(body_tpl, **base_ctx)
    return render_template_string(BASE, body=body, **base_ctx)


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


AUTH = """<div class="card"><h2>{{ title }}</h2>
{% if msg %}<p class="err">{{ msg }}</p>{% endif %}
<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
{{ t.username }}<input type="text" name="username" autocomplete="username">
{{ t.password }}<input type="password" name="password" autocomplete="current-password">
<button>{{ title }}</button></form>
<p><a href="/register">{{ t.register }}</a> | <a href="/login">{{ t.login }}</a></p></div>"""

HOME = """<div class="card"><p>{{ t.subtitle }}</p>
<form method="post" action="/"><input type="hidden" name="csrf" value="{{ csrf }}">
<textarea name="text" maxlength="5000" placeholder="{{ t.placeholder }}">{{ text }}</textarea><br><br>
<button>{{ t.analyze }}</button> &nbsp; <a href="/?sample=1">{{ t.sample }}</a></form></div>
{% if res %}<div class="card">
<h3>{{ t.risk }}: <span class="badge {{ res.level }}">{{ label }}</span> &nbsp; {{ t.score }}: {{ res.score }}/100</h3>
<div class="meter"><div class="bar {{ res.level }}" style="width:{{ res.score }}%"></div></div>
<p><small>{{ t.disclaimer }}</small></p>
{% if res.findings %}<h4>{{ t.why }}</h4>
{% for f in res.findings %}<p><b>{{ f.name }}</b> (+{{ f.points }})<br>{{ f.why }}<br>
<small>{{ t.matched }}:</small> {% for m in f.matches %}<span class="chip">{{ m }}</span>{% endfor %}</p>{% endfor %}{% endif %}
<h4>{{ t.todo }}</h4><ul>{% for a in res.advice %}<li>{{ a }}</li>{% endfor %}</ul>
<form method="post" action="/report"><input type="hidden" name="csrf" value="{{ csrf }}">
<input type="hidden" name="text" value="{{ text }}"><input type="hidden" name="level" value="{{ res.level }}">
<button>{{ t.report }}</button></form></div>{% endif %}
{% if reported %}<p class="ok">{{ t.reported }}</p>{% endif %}
<div class="card"><h3>{{ t.tips }}</h3><ul>{% for x in tips %}<li>{{ x }}</li>{% endfor %}</ul></div>
<div class="card"><h3>{{ t.history }}</h3>
{% if hist %}<table><tr><th>{{ t.time }}</th><th>{{ t.risk }}</th><th>{{ t.score }}</th></tr>
{% for h in hist %}<tr><td>{{ h.ts }}</td><td>{{ h.level }}</td><td>{{ h.score }}</td></tr>{% endfor %}</table>
{% else %}<p>{{ t.nodata }}</p>{% endif %}</div>"""

ADMIN = """<div class="card"><h3>{{ t.admin }}</h3>
<p>{{ t.total }}: <b>{{ stats.total }}</b> | {{ t.high }}: <b>{{ stats.high }}</b> | {{ t.reports }}: <b>{{ stats.reports }}</b></p></div>
<div class="card"><h3>{{ t.audit }}</h3><table><tr><th>{{ t.time }}</th><th>{{ t.user }}</th><th>{{ t.ip }}</th><th>{{ t.event }}</th></tr>
{% for r in logs %}<tr><td>{{ r.ts }}</td><td>{{ r.username }}</td><td>{{ r.ip }}</td><td>{{ r.event }}</td></tr>{% endfor %}</table></div>"""


# ------------------------------------------------------------ routes
@guard_app.route("/lang/<code>")
def set_lang(code):
    if code in LANGS:
        session["lang"] = code
    return redirect("/")


@guard_app.route("/register", methods=["GET", "POST"])
def register():
    t, msg = UI[lang()], ""
    if request.method == "POST":
        u, p = request.form.get("username", "").strip(), request.form.get("password", "")
        if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", u):
            msg = t["bad_user"]
        elif not strong_password(p):
            msg = t["bad_pass"]
        else:
            try:
                db().execute("INSERT INTO users(username, password_hash) VALUES (?,?)", (u, generate_password_hash(p)))
                db().commit()
                log("REGISTER_OK", u)
                return redirect("/login")
            except sqlite3.IntegrityError:
                msg = t["taken"]
    return render_page(AUTH, title=t["register"], msg=msg)


@guard_app.route("/login", methods=["GET", "POST"])
def login():
    t, msg = UI[lang()], ""
    if request.method == "POST":
        u, p = request.form.get("username", "").strip(), request.form.get("password", "")
        user = db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if user and user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > datetime.utcnow():
            log("LOGIN_BLOCKED_LOCKED", u)
            msg = t["locked"]
        elif user and check_password_hash(user["password_hash"], p):
            db().execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user["id"],))
            db().commit()
            keep = session.get("lang", "en")
            session.clear()
            session.update(user=user["username"], role=user["role"], lang=keep)
            log("LOGIN_OK", u)
            return redirect("/")
        else:
            log("LOGIN_FAILED", u)
            if user:
                fails, locked = user["failed_attempts"] + 1, None
                if fails >= MAX_FAILS:
                    locked = (datetime.utcnow() + timedelta(minutes=LOCK_MINUTES)).isoformat()
                    fails = 0
                    log("ACCOUNT_LOCKED", u)
                db().execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?", (fails, locked, user["id"]))
                db().commit()
            msg = t["invalid"]
    return render_page(AUTH, title=t["login"], msg=msg)


@guard_app.route("/logout")
def logout():
    log("LOGOUT", session.get("user"))
    keep = session.get("lang", "en")
    session.clear()
    session["lang"] = keep
    return redirect("/login")


def localize(res, lg):
    """Turn the analyzer output into text for the chosen language."""
    for f in res["findings"]:
        f["name"] = CAT[lg].get(f["category"], f["category"])
        if lg != "en":
            f["why"] = WHY[lg][f["category"]]
    if lg != "en":
        res["advice"] = ADVICE[lg] if res["level"] in ("MEDIUM", "HIGH") else [LOW_ADVICE[lg]]
    return res


@guard_app.route("/", methods=["GET", "POST"])
def home():
    if "user" not in session:
        return redirect("/login")
    lg, t = lang(), UI[lang()]
    text, res = "", None
    if request.method == "POST":
        text = request.form.get("text", "").strip()[:5000]
        if text:
            res = localize(analyze(text), lg)
            db().execute("INSERT INTO scans(ts, username, sha256, preview, score, level, lang) VALUES (?,?,?,?,?,?,?)",
                         (now(), session["user"], hashlib.sha256(text.encode()).hexdigest(), text[:200],
                          res["score"], res["level"], lg))
            db().commit()
            log("SCAN_" + res["level"], session["user"])
    elif request.args.get("sample"):
        text = SAMPLES[lg]
    hist = db().execute("SELECT ts, level, score FROM scans WHERE username=? ORDER BY id DESC LIMIT 8",
                        (session["user"],)).fetchall()
    return render_page(HOME, text=text, res=res, label=t.get(res["level"]) if res else "",
                       hist=hist, tips=TIPS[lg], reported=request.args.get("reported"))


@guard_app.route("/report", methods=["POST"])
def report():
    if "user" not in session:
        return redirect("/login")
    level = request.form.get("level", "")[:10]
    db().execute("INSERT INTO reports(ts, username, preview, level) VALUES (?,?,?,?)",
                 (now(), session["user"], request.form.get("text", "")[:200], level))
    db().commit()
    log("SCAM_REPORTED", session["user"])
    return redirect("/?reported=1")


@guard_app.route("/admin")
def admin():
    if session.get("role") != "admin":  # role-based access control
        log("UNAUTHORIZED_ADMIN_ACCESS", session.get("user"))
        return "Forbidden", 403
    q = lambda sql: db().execute(sql).fetchone()[0]
    stats = dict(total=q("SELECT COUNT(*) FROM scans"), high=q("SELECT COUNT(*) FROM scans WHERE level='HIGH'"),
                 reports=q("SELECT COUNT(*) FROM reports"))
    logs = db().execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 60").fetchall()
    return render_page(ADMIN, stats=stats, logs=logs)


if __name__ == "__main__":
    init_db()
    if len(sys.argv) == 3 and sys.argv[1] == "makeadmin":
        con = sqlite3.connect(DB)
        con.execute("UPDATE users SET role='admin' WHERE username=?", (sys.argv[2],))
        con.commit()
        print("Done:", sys.argv[2], "is now admin")
    else:
        guard_app.run(debug=False)
