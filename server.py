#!/usr/bin/env python3
"""
HomeSystem v6.0 — Premium Remote Power Manager
"""

__version__ = "6.0.0"

import os, sys, time, json, csv, io, socket
import hashlib, shutil, sqlite3, subprocess
import threading, urllib.request
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template_string, jsonify,
    request, redirect, url_for, make_response, Response
)

# ================================================================
#  .ENV LOADER
# ================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def load_dotenv():
    path = os.path.join(SCRIPT_DIR, ".env")
    if not os.path.exists(path):
        print("\n  ✘ FATAL: .env not found!")
        print(f"  Expected at: {path}")
        print("  Run: cp .env.example .env && nano .env\n")
        sys.exit(1)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if v:
                    os.environ.setdefault(k, v)

def env(key, default=None, required=False):
    val = os.environ.get(key, default)
    if required and not val:
        print(f"\n  ✘ FATAL: '{key}' missing in .env\n")
        sys.exit(1)
    return val

load_dotenv()

# ================================================================
#  CONFIG
# ================================================================

class C:
    SECRET     = env("SECRET_KEY", required=True)
    ADMIN      = env("ADMIN_KEY",  required=True)
    PC_NAME    = env("PC_NAME",    required=True)
    PC_IP      = env("PC_IP",      required=True)
    PC_MAC     = env("PC_MAC",     required=True)
    BIND       = env("BIND_HOST",  "0.0.0.0")
    PORT       = int(env("PORT",   "8080"))
    BCAST      = env("BROADCAST",  "")
    EXTRA      = env("EXTRA_TARGETS", "[]")
    TG_TOKEN   = env("TELEGRAM_BOT_TOKEN", "")
    TG_CHAT    = env("TELEGRAM_CHAT_ID", "")
    UPDATE_URL = env("UPDATE_URL", "")
    VERSION_URL= env("VERSION_URL","")
    COOLDOWN   = int(env("WOL_COOLDOWN", "8"))
    PING_SEC   = int(env("PING_INTERVAL","5"))

if not C.BCAST:
    parts = C.PC_IP.rsplit(".", 1)
    C.BCAST = parts[0] + ".255" if len(parts) == 2 else "255.255.255.255"

TARGETS = [{"id":"main","name":C.PC_NAME,"ip":C.PC_IP,"mac":C.PC_MAC}]
try:
    for i, t in enumerate(json.loads(C.EXTRA)):
        t.setdefault("id", f"t{i}")
        TARGETS.append(t)
except:
    pass

# ================================================================
#  GLOBALS
# ================================================================

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()
DB = os.path.join(SCRIPT_DIR, "homesystem.db")
BOOT = time.time()
lock = threading.Lock()

pc = {}
for t in TARGETS:
    pc[t["id"]] = dict(
        name=t["name"], ip=t["ip"], mac=t["mac"],
        online=False, ping_ms=None, last_check="--",
        last_wol=0, wol_count=0, history=[],
        ports={}
    )

sched = dict(active=False, ts=0, target="main", by="")
rates = {}

# ================================================================
#  DATABASE
# ================================================================

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init_db():
    d = db()
    d.executescript("""
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, ip TEXT, device TEXT, ua TEXT,
            action TEXT, detail TEXT, key_hint TEXT);
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, target TEXT, event TEXT, detail TEXT);
        CREATE INDEX IF NOT EXISTS i1 ON logs(ts);
    """)
    d.commit(); d.close()

def detect(ua):
    u = (ua or "").lower()
    for k,v in [("ipad","iPad"),("iphone","iPhone"),("android","Android"),
                ("windows","Win"),("macintosh","Mac"),("linux","Linux"),
                ("curl","cURL"),("python","Py"),("shortcuts","Shortcut")]:
        if k in u: return v
    return "?"

def log_a(action, detail=""):
    try:
        ua = (request.headers.get("User-Agent") or "")[:400]
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        key = request.args.get("key","")
        d = db()
        d.execute("INSERT INTO logs(ts,ip,device,ua,action,detail,key_hint) VALUES(?,?,?,?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, detect(ua), ua,
             action, str(detail)[:200], (key[:2]+"***") if key else "-"))
        d.execute("DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT 5000)")
        d.commit(); d.close()
    except: pass

def log_ev(tid, ev, det=""):
    try:
        d = db()
        d.execute("INSERT INTO events(ts,target,event,detail) VALUES(?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), tid, ev, det))
        d.commit(); d.close()
    except: pass

# ================================================================
#  TELEGRAM
# ================================================================

def tg(msg):
    if not C.TG_TOKEN or not C.TG_CHAT: return
    def _s():
        try:
            data = json.dumps({"chat_id":C.TG_CHAT,"text":msg,"parse_mode":"HTML"}).encode()
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{C.TG_TOKEN}/sendMessage",
                data=data, headers={"Content-Type":"application/json"})
            urllib.request.urlopen(req, timeout=10)
        except: pass
    threading.Thread(target=_s, daemon=True).start()

# ================================================================
#  WOL
# ================================================================

def wol(mac_str, repeat=3):
    mac = bytes.fromhex(mac_str.replace(":","").replace("-",""))
    pkt = b'\xff'*6 + mac*16
    n = 0
    for addr in [C.BCAST, "255.255.255.255"]:
        for port in [7, 9]:
            for _ in range(repeat):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    s.sendto(pkt, (addr, port)); s.close(); n += 1
                except: pass
                time.sleep(0.02)
    return n

# ================================================================
#  PROBES
# ================================================================

def do_ping(ip):
    try:
        out = subprocess.check_output(
            ["ping","-c","1","-W","1",ip],
            stderr=subprocess.DEVNULL, universal_newlines=True, timeout=3)
        if "time=" in out:
            return round(float(out.split("time=")[-1].split(" ")[0]), 1)
    except: pass
    return None

def tcp_ok(ip, port, timeout=0.8):
    try:
        s = socket.socket(); s.settimeout(timeout)
        ok = s.connect_ex((ip, port)) == 0; s.close(); return ok
    except: return False

# ================================================================
#  THREADS
# ================================================================

def _monitor():
    prev = {t["id"]: None for t in TARGETS}
    while True:
        for t in TARGETS:
            tid = t["id"]
            try:
                ms = do_ping(t["ip"])
                on = ms is not None
                if not on:
                    for p in [3389,445,22,80]:
                        if tcp_ok(t["ip"], p): on = True; break
                # port scan when online
                ports = {}
                if on:
                    for name, port in [("RDP",3389),("SSH",22),("SMB",445),("HTTP",80),("HTTPS",443)]:
                        ports[name] = tcp_ok(t["ip"], port, 0.5)
                now_s = datetime.now().strftime("%H:%M:%S")
                with lock:
                    s = pc[tid]
                    s["online"], s["ping_ms"] = on, ms
                    s["last_check"] = now_s
                    s["ports"] = ports
                    s["history"].append({"t":datetime.now().strftime("%H:%M"),"on":on,"ms":ms})
                    if len(s["history"]) > 200: s["history"] = s["history"][-200:]
                if prev[tid] is not None and on != prev[tid]:
                    st = "🟢 ONLINE" if on else "🔴 OFFLINE"
                    log_ev(tid, st); tg(f"{'🟢' if on else '🔴'} <b>{t['name']}</b> {st}")
                prev[tid] = on
            except Exception as e: print(f"[MON] {e}")
        time.sleep(C.PING_SEC)

def _scheduler():
    while True:
        with lock:
            if sched["active"] and time.time() >= sched["ts"]:
                sched["active"] = False
                s = pc.get(sched["target"])
                if s:
                    cnt = wol(s["mac"], 5); s["wol_count"] += cnt
                    log_ev(sched["target"], "⏰ SCHED_WOL", f"{cnt}pkts")
                    tg(f"⏰ Scheduled WOL → <b>{s['name']}</b>")
        time.sleep(2)

# ================================================================
#  AUTH
# ================================================================

def _authed():
    key = request.args.get("key") or request.headers.get("X-API-Key") or ""
    cookie = request.cookies.get("at","")
    h = hashlib.sha256(C.SECRET.encode()).hexdigest()
    return key == C.SECRET or cookie == h

def _is_admin():
    key = request.args.get("admin") or request.headers.get("X-Admin-Key") or ""
    return key == C.ADMIN

def _rate_ok():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    now = time.time()
    rates.setdefault(ip, [])
    rates[ip] = [t for t in rates[ip] if now - t < 60]
    rates[ip].append(now)
    return len(rates[ip]) <= 60

def need_auth(f):
    @wraps(f)
    def w(*a, **kw):
        if not _authed():
            log_a("❌DENY", request.path)
            if request.path.startswith("/api/"): return jsonify({"error":"Unauthorized"}), 401
            return redirect(url_for("login"))
        if not _rate_ok(): return jsonify({"error":"Rate limited"}), 429
        return f(*a, **kw)
    return w

def need_admin(f):
    @wraps(f)
    def w(*a, **kw):
        if not _is_admin():
            log_a("❌ADMIN_DENY", request.path)
            return jsonify({"error":"Admin required"}), 403
        return f(*a, **kw)
    return w

# ================================================================
#  HELPERS
# ================================================================

def uptime():
    s = int(time.time()-BOOT); d,s=divmod(s,86400); h,s=divmod(s,3600); m,s=divmod(s,60)
    return f"{d}d {h}h {m}m" if d else f"{h}h {m}m" if h else f"{m}m {s}s"

def memfree():
    try:
        with open("/proc/meminfo") as f:
            for l in f:
                if "MemAvailable" in l: return f"{int(l.split()[1])//1024}MB"
    except: pass
    return "N/A"

def dbsize():
    try:
        s=os.path.getsize(DB); return f"{s/1048576:.1f}MB" if s>1048576 else f"{s//1024}KB"
    except: return "N/A"

def remote_ver():
    if not C.VERSION_URL: return None
    try:
        with urllib.request.urlopen(C.VERSION_URL, timeout=10) as r: return r.read().decode().strip()
    except: return None

# ================================================================
#  HTML — LOGIN
# ================================================================

LOGIN = r"""
<!DOCTYPE html><html lang="zh"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>HomeSystem</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{
  font-family:-apple-system,'SF Pro Display','Segoe UI',sans-serif;
  min-height:100vh;display:flex;justify-content:center;align-items:center;
  background:#07080f;overflow:hidden;
}
body::before{
  content:'';position:fixed;top:-50%;left:-50%;width:200%;height:200%;
  background:conic-gradient(from 0deg at 50% 50%,
    #07080f 0deg,#1a1040 60deg,#07080f 120deg,
    #0a1628 180deg,#07080f 240deg,#18103a 300deg,#07080f 360deg);
  animation:rot 30s linear infinite;z-index:0;
}
@keyframes rot{to{transform:rotate(360deg)}}
.card{
  position:relative;z-index:1;width:340px;
  background:rgba(12,14,28,0.85);
  backdrop-filter:blur(40px) saturate(1.5);
  border:1px solid rgba(255,255,255,0.06);
  border-radius:28px;padding:48px 36px 40px;
  text-align:center;
  box-shadow:0 30px 80px rgba(0,0,0,0.6),
    inset 0 1px 0 rgba(255,255,255,0.04);
}
.icon{font-size:3em;margin-bottom:12px;display:block}
h2{color:#e8eaf0;font-size:1.3em;font-weight:600;letter-spacing:-.5px}
.sub{color:#555;font-size:.75em;margin:6px 0 28px;letter-spacing:.5px}
input{
  width:100%;padding:15px 18px;border-radius:14px;
  border:1px solid rgba(255,255,255,0.08);
  background:rgba(255,255,255,0.04);
  color:#e8eaf0;font-size:15px;outline:none;
  transition:border .3s,box-shadow .3s;
}
input:focus{
  border-color:rgba(99,102,241,0.5);
  box-shadow:0 0 0 3px rgba(99,102,241,0.15);
}
input::placeholder{color:#444}
.btn{
  width:100%;padding:15px;margin-top:16px;border:none;
  border-radius:14px;font-weight:700;font-size:15px;
  cursor:pointer;color:#fff;letter-spacing:.3px;
  background:linear-gradient(135deg,#6366f1,#8b5cf6);
  box-shadow:0 4px 20px rgba(99,102,241,0.3);
  transition:transform .15s,box-shadow .2s;
}
.btn:hover{box-shadow:0 6px 30px rgba(99,102,241,0.45)}
.btn:active{transform:scale(.97)}
.err{color:#f87171;font-size:.82em;margin-top:14px;min-height:20px}
.ft{color:#333;font-size:.65em;margin-top:20px;line-height:1.6}
</style></head><body>
<div class="card">
  <span class="icon">⚡</span>
  <h2>HomeSystem</h2>
  <p class="sub">REMOTE POWER MANAGER</p>
  <form method="POST">
    <input type="password" name="key" placeholder="Enter access key" required autocomplete="current-password">
    <button class="btn" type="submit">Sign In</button>
  </form>
  <p class="err">{{ error or '' }}</p>
  <p class="ft">v""" + __version__ + r"""</p>
</div></body></html>
"""

# ================================================================
#  HTML — DASHBOARD (Premium UI)
# ================================================================

DASH = r"""
<!DOCTYPE html><html lang="zh-HK"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#07080f">
<title>HomeSystem</title>
<style>
:root{
  --bg:#07080f;--surface:rgba(14,16,32,0.75);
  --border:rgba(255,255,255,0.05);--border-h:rgba(255,255,255,0.1);
  --text:#e2e8f0;--muted:#64748b;--dim:#334155;
  --indigo:#818cf8;--indigo-d:#6366f1;
  --green:#34d399;--red:#f87171;--amber:#fbbf24;
  --purple:#a78bfa;
  --radius:16px;--radius-sm:12px;
}
*{margin:0;padding:0;box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  font-family:-apple-system,'SF Pro Display','Segoe UI','Microsoft YaHei',sans-serif;
  background:var(--bg);color:var(--text);min-height:100vh;
  -webkit-font-smoothing:antialiased;
}
.page{max-width:500px;margin:0 auto;padding:0 14px 30px;
  animation:fadeUp .5s ease}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}

/* ─── Header ─── */
.hdr{
  position:sticky;top:0;z-index:50;
  padding:14px 0 10px;
  background:rgba(7,8,15,0.8);backdrop-filter:blur(20px);
  border-bottom:1px solid var(--border);
  margin-bottom:10px;
}
.hdr-inner{display:flex;justify-content:space-between;align-items:center}
.logo{display:flex;align-items:center;gap:8px}
.logo-icon{font-size:1.4em}
.logo-text{font-size:1.1em;font-weight:700;letter-spacing:-.5px;
  background:linear-gradient(135deg,var(--indigo),var(--purple));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent}
.badge{
  font-size:.6em;padding:2px 8px;border-radius:6px;
  background:rgba(99,102,241,0.15);color:var(--indigo);
  font-weight:600;letter-spacing:.5px;
}
.hdr-actions{display:flex;gap:6px}
.hdr-btn{
  background:rgba(255,255,255,0.04);border:1px solid var(--border);
  border-radius:10px;padding:7px 10px;cursor:pointer;
  color:var(--muted);font-size:.85em;transition:.2s;
}
.hdr-btn:hover{background:rgba(255,255,255,0.08);color:var(--text)}

/* ─── Cards ─── */
.card{
  background:var(--surface);backdrop-filter:blur(20px);
  border:1px solid var(--border);border-radius:var(--radius);
  padding:18px;margin-bottom:10px;
  transition:border-color .3s;
}
.card:hover{border-color:var(--border-h)}
.card-h{
  display:flex;justify-content:space-between;align-items:center;
  margin-bottom:12px;
}
.card-t{font-size:.68em;color:var(--muted);text-transform:uppercase;
  letter-spacing:1.5px;font-weight:600}
.card-a{font-size:.72em;color:var(--muted)}

/* ─── Target tabs ─── */
.tabs{display:flex;gap:4px;padding:2px;
  background:rgba(255,255,255,0.03);border-radius:10px;overflow-x:auto}
.tab{
  padding:8px 16px;border-radius:8px;border:none;
  font-size:.78em;font-weight:600;cursor:pointer;
  color:var(--muted);background:transparent;
  transition:.2s;white-space:nowrap;
}
.tab.on{background:var(--indigo-d);color:#fff;
  box-shadow:0 2px 10px rgba(99,102,241,0.3)}

/* ─── Status ─── */
.status-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.stat{
  background:rgba(255,255,255,0.02);border-radius:var(--radius-sm);
  padding:16px;text-align:center;position:relative;overflow:hidden;
}
.stat::after{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  border-radius:2px;opacity:0;transition:opacity .3s;
}
.stat.ok::after{background:var(--green);opacity:1}
.stat.off::after{background:var(--red);opacity:1}
.stat-label{font-size:.7em;color:var(--muted);margin-bottom:6px;letter-spacing:.5px}
.stat-val{font-size:1.6em;font-weight:800;font-variant-numeric:tabular-nums}

.orb{
  width:14px;height:14px;border-radius:50%;
  display:inline-block;vertical-align:middle;margin-right:4px;
}
.orb.on{background:var(--green);box-shadow:0 0 12px var(--green),0 0 30px rgba(52,211,153,0.2);
  animation:glow 2.5s ease-in-out infinite}
.orb.off{background:var(--red);box-shadow:0 0 12px var(--red);
  animation:glow 2.5s ease-in-out infinite}
@keyframes glow{0%,100%{opacity:1}50%{opacity:.35}}

.meta{display:flex;justify-content:space-between;
  margin-top:10px;font-size:.7em;color:var(--muted)}
.meta b{color:var(--text);font-weight:600}

/* ─── Timeline ─── */
.timeline{display:flex;align-items:flex-end;gap:1px;height:24px;margin-top:10px}
.tbar{flex:1;min-width:2px;border-radius:2px 2px 0 0;transition:height .4s ease}

/* ─── Ports ─── */
.ports{display:flex;gap:4px;flex-wrap:wrap;margin-top:8px}
.port{
  font-size:.65em;padding:3px 8px;border-radius:6px;
  font-weight:600;letter-spacing:.3px;
}
.port.up{background:rgba(52,211,153,0.1);color:var(--green)}
.port.dn{background:rgba(248,113,113,0.08);color:rgba(248,113,113,0.4)}

/* ─── Buttons ─── */
.btns{display:grid;grid-template-columns:1fr 1fr;gap:6px}
.btn{
  padding:14px;border:none;border-radius:var(--radius-sm);
  font-weight:700;font-size:.82em;cursor:pointer;
  transition:transform .12s,box-shadow .2s;
  position:relative;overflow:hidden;letter-spacing:.3px;
}
.btn:active:not(:disabled){transform:scale(.95)}
.btn:disabled{opacity:.25;cursor:not-allowed}
.btn::after{
  content:'';position:absolute;top:0;left:-100%;width:100%;height:100%;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,0.08),transparent);
  transition:left .5s;
}
.btn:hover:not(:disabled)::after{left:100%}
.b-wol{background:linear-gradient(135deg,#6366f1,#818cf8);color:#fff;
  box-shadow:0 4px 15px rgba(99,102,241,0.25)}
.b-combo{background:linear-gradient(135deg,#0ea5e9,#38bdf8);color:#fff;
  box-shadow:0 4px 15px rgba(14,165,233,0.2)}
.b-force{background:linear-gradient(135deg,#f59e0b,#fbbf24);color:#1a1a2e;
  box-shadow:0 4px 15px rgba(245,158,11,0.2)}
.b-nuke{background:linear-gradient
