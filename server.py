#!/usr/bin/env python3
"""
HomeSystem Remote Power Manager v5.0
Zero-leak · SSH-first · Multi-target
"""

__version__ = "5.0.0"

import os, sys, time, json, csv, io, socket
import hashlib, shutil, sqlite3, subprocess
import threading, urllib.request
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template_string, jsonify, request,
    redirect, url_for, make_response, Response
)

# ================================================================
#  .ENV LOADER — 代码里零密钥，全部从文件读取
# ================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def load_dotenv():
    path = os.path.join(SCRIPT_DIR, ".env")
    if not os.path.exists(path):
        print("\n" + "=" * 50)
        print("  FATAL: .env file not found!")
        print(f"  Expected: {path}")
        print("  Fix:  cp .env.example .env && nano .env")
        print("=" * 50)
        sys.exit(1)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if (line and not line.startswith("#")
                    and "=" in line):
                k, _, v = line.partition("=")
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if v:
                    os.environ.setdefault(k, v)

def env(key, fallback=None, required=False):
    val = os.environ.get(key, fallback)
    if required and not val:
        print(f"\n  FATAL: Required variable '{key}' "
              f"missing from .env")
        sys.exit(1)
    return val

load_dotenv()

# ================================================================
#  CONFIG — 全部来自 .env，绝不硬编码
# ================================================================

class C:
    SECRET      = env("SECRET_KEY",  required=True)
    ADMIN       = env("ADMIN_KEY",   required=True)
    PC_NAME     = env("PC_NAME",     required=True)
    PC_IP       = env("PC_IP",       required=True)
    PC_MAC      = env("PC_MAC",      required=True)

    BIND        = env("BIND_HOST",   "127.0.0.1")
    PORT        = int(env("PORT",    "8080"))
    BCAST       = env("BROADCAST",   "")

    EXTRA       = env("EXTRA_TARGETS", "[]")

    TG_TOKEN    = env("TELEGRAM_BOT_TOKEN", "")
    TG_CHAT     = env("TELEGRAM_CHAT_ID",   "")

    UPDATE_URL  = env("UPDATE_URL",  "")
    VERSION_URL = env("VERSION_URL", "")

    COOLDOWN    = int(env("WOL_COOLDOWN",   "8"))
    PING_INT    = int(env("PING_INTERVAL",  "5"))
    MAX_LOGS    = int(env("MAX_LOGS",       "5000"))
    SESS_DAYS   = int(env("SESSION_DAYS",   "30"))

# 自动计算广播地址
if not C.BCAST:
    p = C.PC_IP.rsplit(".", 1)
    C.BCAST = (p[0] + ".255") if len(p) == 2 else "255.255.255.255"

# 解析多目标
def _parse_targets():
    targets = [{
        "id": "main", "name": C.PC_NAME,
        "ip": C.PC_IP, "mac": C.PC_MAC
    }]
    try:
        for i, t in enumerate(json.loads(C.EXTRA)):
            t.setdefault("id", f"t{i}")
            targets.append(t)
    except:
        pass
    return targets

TARGETS = _parse_targets()

# ================================================================
#  GLOBALS
# ================================================================

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()

DB_PATH    = os.path.join(SCRIPT_DIR, "homesystem.db")
BOOT_TIME  = time.time()
state_lock = threading.Lock()
sched_lock = threading.Lock()

# 每台PC的状态
pc_states = {}
for t in TARGETS:
    pc_states[t["id"]] = {
        "name": t["name"], "ip": t["ip"], "mac": t["mac"],
        "online": False, "ping_ms": None,
        "last_check": "never", "last_wol": 0,
        "wol_count": 0, "history": [],
    }

scheduled = {"active": False, "ts": 0,
             "target": "main", "by": ""}

rate_map = {}

# ================================================================
#  DATABASE
# ================================================================

def get_db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS access_log (
        id     INTEGER PRIMARY KEY AUTOINCREMENT,
        ts     TEXT NOT NULL, ip TEXT NOT NULL,
        device TEXT, ua TEXT, action TEXT NOT NULL,
        detail TEXT, key_hint TEXT
    );
    CREATE TABLE IF NOT EXISTS events (
        id     INTEGER PRIMARY KEY AUTOINCREMENT,
        ts     TEXT NOT NULL, target TEXT,
        event  TEXT NOT NULL, detail TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_al_ts
        ON access_log(ts);
    CREATE INDEX IF NOT EXISTS idx_ev_ts
        ON events(ts);
    """)
    db.commit()
    db.close()

def _device(ua):
    u = (ua or "").lower()
    for k, v in [
        ("ipad","📱iPad"), ("iphone","📱iPhone"),
        ("android","📱Android"), ("windows","💻Win"),
        ("macintosh","💻Mac"), ("linux","🐧Linux"),
        ("curl","🔧cURL"), ("python","🐍Py"),
        ("shortcuts","⚡Shortcut"),
    ]:
        if k in u:
            return v
    return "❓"

def log_access(action, detail=""):
    try:
        ua = (request.headers.get("User-Agent") or "")[:400]
        ip = request.headers.get(
            "X-Forwarded-For", request.remote_addr)
        key = request.args.get("key", "")
        db = get_db()
        db.execute(
            """INSERT INTO access_log
               (ts,ip,device,ua,action,detail,key_hint)
               VALUES(?,?,?,?,?,?,?)""",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             ip, _device(ua), ua, action,
             str(detail)[:200],
             (key[:2] + "***") if key else "none")
        )
        db.execute(
            f"DELETE FROM access_log WHERE id NOT IN "
            f"(SELECT id FROM access_log "
            f"ORDER BY id DESC LIMIT {C.MAX_LOGS})")
        db.commit()
        db.close()
    except Exception as e:
        print(f"[DB] {e}")

def log_event(target_id, event, detail=""):
    try:
        db = get_db()
        db.execute(
            "INSERT INTO events (ts,target,event,detail) "
            "VALUES(?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             target_id, event, detail))
        db.commit()
        db.close()
    except:
        pass

# ================================================================
#  TELEGRAM NOTIFICATIONS
# ================================================================

def tg_send(msg):
    if not C.TG_TOKEN or not C.TG_CHAT:
        return
    def _send():
        try:
            url = (f"https://api.telegram.org/"
                   f"bot{C.TG_TOKEN}/sendMessage")
            data = json.dumps({
                "chat_id": C.TG_CHAT,
                "text": msg,
                "parse_mode": "HTML"
            }).encode()
            req = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            print(f"[TG] {e}")
    threading.Thread(target=_send, daemon=True).start()

# ================================================================
#  WOL — 纯 Python
# ================================================================

def send_wol(mac_str, repeat=3):
    mac = bytes.fromhex(
        mac_str.replace(":", "").replace("-", ""))
    magic = b'\xff' * 6 + mac * 16
    sent = 0
    for addr in [C.BCAST, "255.255.255.255"]:
        for port in [7, 9]:
            for _ in range(repeat):
                try:
                    s = socket.socket(
                        socket.AF_INET, socket.SOCK_DGRAM)
                    s.setsockopt(
                        socket.SOL_SOCKET,
                        socket.SO_BROADCAST, 1)
                    s.sendto(magic, (addr, port))
                    s.close()
                    sent += 1
                except:
                    pass
                time.sleep(0.02)
    return sent

# ================================================================
#  NETWORK PROBES
# ================================================================

def ping(ip):
    try:
        out = subprocess.check_output(
            ["ping", "-c", "1", "-W", "1", ip],
            stderr=subprocess.DEVNULL,
            universal_newlines=True, timeout=3)
        if "time=" in out:
            return round(float(
                out.split("time=")[-1].split(" ")[0]), 1)
    except:
        pass
    return None

def tcp_check(ip, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ok = s.connect_ex((ip, port)) == 0
        s.close()
        return ok
    except:
        return False

# ================================================================
#  BACKGROUND THREADS
# ================================================================

def _monitor():
    prev = {t["id"]: None for t in TARGETS}
    while True:
        for t in TARGETS:
            tid = t["id"]
            try:
                ms = ping(t["ip"])
                online = ms is not None
                if not online:
                    for p in [3389, 445, 22, 80]:
                        if tcp_check(t["ip"], p):
                            online = True
                            break
                now_s = datetime.now().strftime("%H:%M:%S")
                with state_lock:
                    st = pc_states[tid]
                    st["online"] = online
                    st["ping_ms"] = ms
                    st["last_check"] = now_s
                    st["history"].append({
                        "t": datetime.now().strftime("%H:%M"),
                        "on": online, "ms": ms
                    })
                    if len(st["history"]) > 200:
                        st["history"] = st["history"][-200:]

                if prev[tid] is not None and online != prev[tid]:
                    state_str = "🟢 ONLINE" if online else "🔴 OFFLINE"
                    log_event(tid, state_str)
                    tg_send(
                        f"{'🟢' if online else '🔴'} "
                        f"<b>{t['name']}</b> is now "
                        f"{'ONLINE' if online else 'OFFLINE'}")
                    print(f"[MON] {t['name']} {state_str}")
                prev[tid] = online
            except Exception as e:
                print(f"[MON] {tid}: {e}")
        time.sleep(C.PING_INT)

def _scheduler():
    while True:
        with sched_lock:
            if (scheduled["active"]
                    and time.time() >= scheduled["ts"]):
                scheduled["active"] = False
                tid = scheduled["target"]
                t = pc_states.get(tid)
                if t:
                    cnt = send_wol(t["mac"], repeat=5)
                    t["wol_count"] += cnt
                    log_event(tid, "⏰ SCHEDULED_WOL",
                              f"{cnt} packets")
                    tg_send(f"⏰ Scheduled WOL fired for "
                            f"<b>{t['name']}</b>")
                    print(f"[SCHED] WOL fired → {t['name']}")
        time.sleep(2)

# ================================================================
#  AUTH & RATE LIMIT
# ================================================================

def _check_auth():
    key = (request.args.get("key")
           or request.headers.get("X-API-Key") or "")
    cookie = request.cookies.get("auth_token", "")
    expected = hashlib.sha256(C.SECRET.encode()).hexdigest()
    return key == C.SECRET or cookie == expected

def _check_admin():
    key = (request.args.get("admin")
           or request.headers.get("X-Admin-Key") or "")
    return key == C.ADMIN

def _rate_ok():
    ip = request.headers.get(
        "X-Forwarded-For", request.remote_addr)
    now = time.time()
    if ip not in rate_map:
        rate_map[ip] = []
    rate_map[ip] = [t for t in rate_map[ip] if now - t < 60]
    rate_map[ip].append(now)
    return len(rate_map[ip]) <= 60

def auth_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not _check_auth():
            log_access("❌AUTH_FAIL", request.path)
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login"))
        if not _rate_ok():
            return jsonify({"error": "Rate limited"}), 429
        return f(*a, **kw)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not _check_admin():
            log_access("❌ADMIN_FAIL", request.path)
            return jsonify({"error": "Admin required"}), 403
        return f(*a, **kw)
    return w

# ================================================================
#  HELPERS
# ================================================================

def _uptime():
    s = int(time.time() - BOOT_TIME)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if d: return f"{d}d{h}h{m}m"
    if h: return f"{h}h{m}m"
    return f"{m}m{s}s"

def _mem():
    try:
        with open("/proc/meminfo") as f:
            for l in f:
                if "MemAvailable" in l:
                    return f"{int(l.split()[1])//1024}MB"
    except:
        pass
    return "N/A"

def _dbsize():
    try:
        s = os.path.getsize(DB_PATH)
        return (f"{s/1048576:.1f}MB" if s > 1048576
                else f"{s//1024}KB")
    except:
        return "N/A"

def _remote_ver():
    if not C.VERSION_URL:
        return None
    try:
        with urllib.request.urlopen(
                C.VERSION_URL, timeout=10) as r:
            return r.read().decode().strip()
    except:
        return None

# ================================================================
#  HTML — LOGIN
# ================================================================

LOGIN_PAGE = """
<!DOCTYPE html><html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport"
  content="width=device-width,initial-scale=1,maximum-scale=1">
<title>🔐 Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,sans-serif;
  background:linear-gradient(135deg,#0b0e17,#1a1a3e);
  display:flex;justify-content:center;align-items:center;
  height:100vh;color:#fff}
.c{background:rgba(255,255,255,.05);backdrop-filter:blur(20px);
  padding:40px 30px;border-radius:24px;width:320px;
  text-align:center;border:1px solid rgba(255,255,255,.06);
  box-shadow:0 20px 60px rgba(0,0,0,.5)}
h2{margin-bottom:6px}
.s{color:#555;font-size:.78em;margin-bottom:20px}
input{padding:14px;width:100%;margin:8px 0 14px;
  border-radius:12px;border:1px solid rgba(255,255,255,.1);
  background:rgba(255,255,255,.04);color:#fff;
  font-size:16px;outline:none}
input:focus{border-color:#007AFF}
.b{width:100%;padding:14px;background:#007AFF;color:#fff;
  border:none;border-radius:12px;font-weight:700;
  font-size:16px;cursor:pointer}
.b:active{transform:scale(.96)}
.e{color:#ff4757;font-size:.83em;margin-top:10px;
  min-height:20px}
.ssh{color:#444;font-size:.7em;margin-top:16px;
  line-height:1.6}
</style>
</head><body>
<div class="c">
  <h2>🔐 HomeSystem</h2>
  <p class="s">SSH Tunnel Required</p>
  <form method="POST">
    <input type="password" name="key"
      placeholder="Enter secret key" required>
    <button class="b" type="submit">Authenticate</button>
  </form>
  <p class="e">{{ error or '' }}</p>
  <p class="ssh">
    🔒 This server binds to 127.0.0.1<br>
    Access via SSH tunnel only
  </p>
</div>
</body></html>
"""

# ================================================================
#  HTML — DASHBOARD
# ================================================================

DASHBOARD_PAGE = r"""
<!DOCTYPE html><html lang="zh-HK">
<head>
<meta charset="UTF-8">
<meta name="viewport"
  content="width=device-width,initial-scale=1,
           maximum-scale=1,user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style"
  content="black-translucent">
<title>⚡ HomeSystem</title>
<style>
:root{--bg:#0b0e17;--c:rgba(255,255,255,.04);
  --br:rgba(255,255,255,.06);--t:#c8d6e5;--d:#555;
  --ac:#00d4ff;--g:#00ff88;--r:#ff4757;--o:#ffa502}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,'SF Pro','Microsoft YaHei',
  sans-serif;background:var(--bg);color:var(--t);
  min-height:100vh;padding:10px;
  -webkit-font-smoothing:antialiased}
.w{max-width:540px;margin:0 auto}
.hd{text-align:center;padding:12px 0 4px}
.hd h1{font-size:1.3em;color:var(--ac);
  text-shadow:0 0 20px rgba(0,212,255,.12)}
.hd .s{color:var(--d);font-size:.68em;margin-top:2px}
.ver{display:inline-block;background:rgba(0,212,255,.08);
  color:var(--ac);padding:1px 7px;border-radius:8px;
  font-size:.62em;margin-top:3px}

.cd{background:var(--c);border:1px solid var(--br);
  border-radius:14px;padding:14px;margin:7px 0;
  backdrop-filter:blur(10px)}
.ct{font-size:.68em;color:var(--d);text-transform:uppercase;
  letter-spacing:1.5px;margin-bottom:8px;display:flex;
  justify-content:space-between;align-items:center}

.g2{display:grid;grid-template-columns:1fr 1fr;gap:6px}
.sb{background:rgba(255,255,255,.02);border-radius:10px;
  padding:10px;text-align:center}
.sb .l{font-size:.68em;color:var(--d)}
.sb .v{font-size:1.3em;font-weight:700;margin-top:2px}

.dt{width:10px;height:10px;border-radius:50%;
  display:inline-block;vertical-align:middle;margin-right:3px}
.dt-on{background:var(--g);box-shadow:0 0 8px var(--g);
  animation:p 2s infinite}
.dt-off{background:var(--r);box-shadow:0 0 8px var(--r);
  animation:p 2s infinite}
@keyframes p{50%{opacity:.3}}

.tl{display:flex;align-items:flex-end;gap:1px;height:24px;
  margin-top:6px}
.tb{flex:1;min-width:2px;border-radius:1px 1px 0 0}

.br{display:grid;grid-template-columns:1fr 1fr;gap:5px}
.b{padding:12px;border:none;border-radius:10px;
  font-weight:700;font-size:.82em;cursor:pointer;
  transition:.15s;letter-spacing:.3px}
.b:active:not(:disabled){transform:scale(.95)}
.b:disabled{opacity:.3;cursor:not-allowed}
.b1{background:linear-gradient(135deg,#6c5ce7,#a29bfe);color:#fff}
.b2{background:linear-gradient(135deg,#0984e3,#74b9ff);color:#fff}
.b3{background:linear-gradient(135deg,#00b894,#55efc4);color:#222}
.b4{background:linear-gradient(135deg,#d63031,#e17055);
  color:#fff;grid-column:1/-1}

/* Target selector */
.ts{display:flex;gap:4px;margin-bottom:8px;flex-wrap:wrap}
.ts .tb{padding:6px 12px;border-radius:8px;border:none;
  font-size:.75em;cursor:pointer;font-weight:600;
  background:rgba(255,255,255,.06);color:var(--d);
  transition:.15s}
.ts .tb.active{background:var(--ac);color:#000}

/* Schedule */
.sr{display:flex;gap:5px;margin-top:6px;align-items:center}
.sr input{flex:1;padding:9px;border-radius:8px;
  border:1px solid var(--br);background:rgba(255,255,255,.04);
  color:#fff;font-size:.85em;outline:none}
.ss{font-size:.72em;color:var(--o);margin-top:4px;
  min-height:16px}

/* Logs */
.lw{max-height:250px;overflow-y:auto;
  -webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;font-size:.7em}
th{color:var(--d);text-align:left;padding:4px 3px;
  border-bottom:1px solid var(--br);
  position:sticky;top:0;background:var(--bg);z-index:1}
td{padding:3px;border-bottom:1px solid var(--br)}
tr:hover td{background:rgba(255,255,255,.02)}
.tg{display:inline-block;padding:1px 5px;border-radius:3px;
  font-size:.8em;font-weight:600}
.tw{background:rgba(108,92,231,.2);color:#a29bfe}
.tf{background:rgba(255,71,87,.15);color:#ff6b81}
.tp{background:rgba(9,132,227,.12);color:#74b9ff}
.ta{background:rgba(255,165,2,.12);color:#ffa502}
.tk{background:rgba(0,255,136,.1);color:#00ff88}

.ig{display:grid;grid-template-columns:1fr 1fr;
  gap:3px;font-size:.72em}
.ig div{padding:5px 7px;background:rgba(255,255,255,.02);
  border-radius:6px}
.ig .lb{color:var(--d)}

.ft{text-align:center;color:#333;font-size:.62em;
  margin-top:8px;padding:5px}
.ft a{color:var(--ac);text-decoration:none}

.toast{position:fixed;bottom:28px;left:50%;
  transform:translateX(-50%) translateY(80px);
  background:rgba(0,0,0,.9);color:#fff;
  padding:9px 20px;border-radius:20px;font-size:.82em;
  transition:transform .3s;z-index:999;pointer-events:none;
  border:1px solid rgba(255,255,255,.05);max-width:92%;
  text-align:center}
.toast.show{transform:translateX(-50%) translateY(0)}

.mbg{position:fixed;top:0;left:0;width:100%;height:100%;
  background:rgba(0,0,0,.7);display:none;z-index:99;
  justify-content:center;align-items:center;
  backdrop-filter:blur(3px)}
.mbg.show{display:flex}
.mdl{background:#1a1a2e;border-radius:18px;padding:20px;
  width:92%;max-width:420px;max-height:80vh;overflow-y:auto;
  border:1px solid var(--br)}
.mdl h3{color:var(--ac);margin-bottom:10px}
.mdl .x{float:right;background:none;border:none;
  color:var(--d);font-size:1.4em;cursor:pointer}

::-webkit-scrollbar{width:3px}
::-webkit-scrollbar-thumb{background:#333;border-radius:3px}
@media(max-width:400px){
  .g2,.br,.ig{grid-template-columns:1fr}
}
</style>
</head><body>
<div class="w">
  <div class="hd">
    <h1>⚡ HomeSystem</h1>
    <div class="s">SSH-First · Zero-Leak · Multi-Target</div>
    <span class="ver">v{{ version }}</span>
  </div>

  <!-- TARGET SELECTOR -->
  <div class="cd">
    <div class="ct"><span>🎯 目标选择</span></div>
    <div class="ts" id="targetBtns"></div>
  </div>

  <!-- STATUS -->
  <div class="cd">
    <div class="ct">
      <span>📊 <span id="curName">--</span></span>
      <span id="chk" style="font-size:1em">--</span>
    </div>
    <div class="g2">
      <div class="sb">
        <div class="l">状态</div>
        <div class="v">
          <span id="dot" class="dt dt-off"></span>
          <span id="stT" style="font-size:.55em">--</span>
        </div>
      </div>
      <div class="sb">
        <div class="l">Ping</div>
        <div class="v">
          <span id="pgV">--</span>
          <span style="font-size:.4em">ms</span>
        </div>
      </div>
    </div>
    <div style="margin-top:5px;font-size:.7em;color:var(--d);
      display:flex;justify-content:space-between">
      <span>📡 Latency: <b id="myL">--</b>ms</span>
      <span>📦 WOL: <b id="wCnt">0</b></span>
    </div>
    <div class="tl" id="tline"></div>
  </div>

  <!-- CONTROLS -->
  <div class="cd">
    <div class="ct"><span>🎛️ 控制</span></div>
    <div class="br">
      <button class="b b1" onclick="act('wol')">📡 WOL</button>
      <button class="b b2" onclick="act('combo')">🚀 双倍</button>
      <button class="b b3" onclick="act('force')">💥 ×10</button>
      <button class="b b4" onclick="cfm()">☢️ 超级轰炸 ×30</button>
    </div>
  </div>

  <!-- SCHEDULE -->
  <div class="cd">
    <div class="ct"><span>⏰ 定时唤醒</span></div>
    <div class="sr">
      <input type="number" id="schM" placeholder="分钟"
        min="1" max="1440" value="30">
      <button class="b b2" style="padding:9px 14px"
        onclick="setSch()">设定</button>
      <button class="b" style="padding:9px 14px;
        background:#444;color:#fff"
        onclick="canSch()">取消</button>
    </div>
    <div class="ss" id="schS">未设定</div>
  </div>

  <!-- LOGS -->
  <div class="cd">
    <div class="ct">
      <span>📋 日志</span>
      <span style="display:flex;gap:6px;align-items:center">
        <span id="lCnt" style="color:var(--ac);font-size:1em">0</span>
        <button onclick="lLogs()"
          style="background:none;border:none;color:var(--ac);
          cursor:pointer;font-size:.95em">🔄</button>
        <button onclick="exportCSV()"
          style="background:none;border:none;color:var(--o);
          cursor:pointer;font-size:.95em">📥</button>
      </span>
    </div>
    <div class="lw">
      <table>
        <thead><tr><th>时间</th><th>设备</th>
          <th>IP</th><th>动作</th></tr></thead>
        <tbody id="lTb">
          <tr><td colspan="4" style="text-align:center;
            color:var(--d)">Loading...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- SYS INFO -->
  <div class="cd">
    <div class="ct"><span>🖥️ 系统</span></div>
    <div class="ig">
      <div><span class="lb">运行</span><br>
        <b id="sU">--</b></div>
      <div><span class="lb">内存</span><br>
        <b id="sM">--</b></div>
      <div><span class="lb">数据库</span><br>
        <b id="sD">--</b></div>
      <div><span class="lb">绑定</span><br>
        <b id="sB">--</b></div>
    </div>
  </div>

  <div class="ft">
    <a href="#" onclick="chkUpd();return false">🔄 更新</a>
    &nbsp;|&nbsp;
    <a href="/logout" style="color:var(--r)">🚪 登出</a>
    &nbsp;|&nbsp;
    <a href="#" onclick="showHelp();return false">❓ 帮助</a>
  </div>
</div>

<div class="toast" id="toast"></div>
<div class="mbg" id="mBg" onclick="cM()">
  <div class="mdl" onclick="event.stopPropagation()">
    <button class="x" onclick="cM()">×</button>
    <div id="mC"></div>
  </div>
</div>

<script>
const K=new URLSearchParams(location.search).get('key')||'';
const AD=new URLSearchParams(location.search).get('admin')||'';
const $=id=>document.getElementById(id);
const TARGETS=JSON.parse('{{ targets_json|safe }}');
let curTarget=TARGETS[0].id;

function toast(m){const t=$('toast');t.textContent=m;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),3500)}
function sM(h){$('mC').innerHTML=h;$('mBg').classList.add('show')}
function cM(){$('mBg').classList.remove('show')}

function api(p,cb){
  const s=p.includes('?')?'&':'?';
  fetch(p+s+'key='+K).then(r=>r.json()).then(cb)
    .catch(e=>toast('❌ '+e));
}

/* Target selector */
function renderTargets(){
  const c=$('targetBtns');c.innerHTML='';
  TARGETS.forEach(t=>{
    const b=document.createElement('button');
    b.className='tb'+(t.id===curTarget?' active':'');
    b.textContent=t.name;
    b.onclick=()=>{curTarget=t.id;renderTargets();refresh()};
    c.appendChild(b);
  });
}
renderTargets();

function act(cmd){
  document.querySelectorAll('.b').forEach(b=>b.disabled=true);
  api('/api/'+cmd+'?target='+curTarget,d=>{
    toast(d.message||d.error||'Done');refresh()});
  setTimeout(()=>document.querySelectorAll('.b')
    .forEach(b=>b.disabled=false),2000);
}
function cfm(){
  if(!confirm('⚠️ Confirm 30-round WOL blast?'))return;
  act('superforce');
}

function setSch(){
  const m=parseInt($('schM').value);
  if(!m||m<1){toast('Invalid minutes');return}
  api('/api/schedule?minutes='+m+'&target='+curTarget,
    d=>{toast(d.message);rSch()});
}
function canSch(){
  api('/api/schedule/cancel',d=>{toast(d.message);rSch()});
}
function rSch(){
  api('/api/schedule/status',d=>{
    if(d.active){
      const r=Math.max(0,Math.ceil((d.ts-Date.now()/1000)/60));
      $('schS').innerHTML='⏰ Fires in <b>'+r+'</b>min';
      $('schS').style.color='var(--o)';
    }else{
      $('schS').textContent='未设定';
      $('schS').style.color='var(--d)';
    }
  });
}

function refresh(){
  const t0=Date.now();
  api('/api/status?target='+curTarget,d=>{
    $('myL').textContent=Date.now()-t0;
    $('curName').textContent=d.name||'--';
    $('dot').className='dt '+(d.online?'dt-on':'dt-off');
    $('stT').textContent=d.online?'ONLINE ✅':'OFFLINE ❌';
    $('pgV').textContent=d.ping_ms!==null?d.ping_ms:'--';
    $('chk').textContent=d.last_check||'--';
    $('wCnt').textContent=d.wol_count||0;
    const tl=$('tline');tl.innerHTML='';
    (d.history||[]).slice(-80).forEach(h=>{
      const b=document.createElement('div');b.className='tb';
      b.style.height=h.on?'100%':'12%';
      b.style.background=h.on?'var(--g)':'var(--r)';
      b.style.opacity=h.on?'0.5':'0.2';
      b.title=h.t+' '+(h.on?'ON':'OFF');tl.appendChild(b);
    });
  });
}

function rSys(){
  api('/api/sysinfo',d=>{
    $('sU').textContent=d.uptime||'--';
    $('sM').textContent=d.mem||'--';
    $('sD').textContent=d.db||'--';
    $('sB').textContent=d.bind||'--';
  });
}

function tagH(a){
  const l=a.toLowerCase();
  if(l.includes('wol'))  return '<span class="tg tw">WOL</span>';
  if(l.includes('fail')) return '<span class="tg tf">'+a+'</span>';
  if(l.includes('page')) return '<span class="tg tp">PAGE</span>';
  if(l.includes('login'))return '<span class="tg tk">LOGIN</span>';
  if(l.includes('admin'))return '<span class="tg ta">ADMIN</span>';
  if(l.includes('sched'))return '<span class="tg ta">TIMER</span>';
  return '<span class="tg">'+a+'</span>';
}
function lLogs(){
  api('/api/logs?n=60',d=>{
    $('lCnt').textContent=(d.total||0);
    const tb=$('lTb');
    if(!d.logs||!d.logs.length){
      tb.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--d)">Empty</td></tr>';
      return}
    tb.innerHTML=d.logs.map(l=>
      '<tr><td style="white-space:nowrap;font-size:.9em">'+
      (l.ts||'').slice(5)+'</td><td>'+(l.device||'')+
      '</td><td style="font-size:.85em;color:var(--d)">'+
      (l.ip||'').split(',')[0]+
      '</td><td>'+tagH(l.action||'')+'</td></tr>').join('');
  });
}

function exportCSV(){
  window.open('/api/logs/export?key='+K,'_blank');
  toast('📥 Downloading CSV...');
}

function chkUpd(){
  toast('Checking...');
  api('/api/check_update',d=>{
    let h='<h3>🔄 Update</h3>';
    h+='<p>Current: <b>'+d.current+'</b></p>';
    h+='<p>Remote: <b>'+(d.remote||'N/A')+'</b></p>';
    if(d.update_available){
      h+='<p style="color:var(--g);margin:10px 0">New version!</p>';
      h+='<button class="b b2" style="width:100%;margin:6px 0" '+
        'onclick="doUpd()">📥 Update Now</button>';
    }else{h+='<p style="color:var(--d);margin:10px 0">Up to date</p>'}
    h+='<button class="b" style="width:100%;margin:6px 0;'+
      'background:#555;color:#fff" onclick="doRollback()">⏪ Rollback</button>';
    sM(h);
  });
}
function doUpd(){
  if(!confirm('Update? Current version will be backed up.'))return;
  toast('Updating...');
  fetch('/admin/update?admin='+AD+'&key='+K)
    .then(r=>r.json()).then(d=>{
    sM('<h3>'+d.message+'</h3><p>'+(d.detail||'')+
      '</p><p style="color:var(--d);margin-top:10px">'+
      'Refreshing in 5s...</p>');
    setTimeout(()=>location.reload(),5000);
  }).catch(e=>toast('Failed: '+e));
}
function doRollback(){
  if(!confirm('Rollback to previous version?'))return;
  fetch('/admin/rollback?admin='+AD+'&key='+K)
    .then(r=>r.json()).then(d=>{
    toast(d.message);setTimeout(()=>location.reload(),3000);
  }).catch(e=>toast('Failed: '+e));
}

function showHelp(){sM(`
<h3>❓ Help</h3>
<div style="font-size:.83em;line-height:1.8">
<p><b>🔒 SSH Tunnel:</b></p>
<code style="font-size:.8em;color:var(--ac);display:block;
  margin:4px 0;word-break:break-all">
ssh -L 8080:127.0.0.1:8080 -p 8022 phone_ip</code>
<p>Then open: <code>http://localhost:8080/?key=...</code></p>
<hr style="border-color:var(--br);margin:8px 0">
<p><b>📡 iPhone Shortcut API:</b></p>
<code style="font-size:.8em;color:var(--ac);display:block;
  margin:4px 0;word-break:break-all">
GET /api/wol?key=YOUR_KEY&target=main</code>
<hr style="border-color:var(--br);margin:8px 0">
<p><b>🤖 Telegram:</b> Set TELEGRAM_BOT_TOKEN and
TELEGRAM_CHAT_ID in .env for state-change alerts</p>
<hr style="border-color:var(--br);margin:8px 0">
<p><b>🎯 Multi-target:</b> Add EXTRA_TARGETS in .env</p>
</div>`);}

setInterval(refresh,4000);
setInterval(rSch,15000);
setInterval(lLogs,20000);
setInterval(rSys,30000);
refresh();rSys();rSch();
setTimeout(lLogs,300);
</script>
</body></html>
"""

# ================================================================
#  ROUTES — AUTH
# ================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        if request.form.get("key") == C.SECRET:
            log_access("✅LOGIN_OK")
            resp = make_response(redirect("/"))
            resp.set_cookie(
                "auth_token",
                hashlib.sha256(C.SECRET.encode()).hexdigest(),
                max_age=86400 * C.SESS_DAYS,
                httponly=True, samesite="Lax")
            return resp
        error = "Wrong key"
        log_access("❌LOGIN_FAIL")
    return render_template_string(LOGIN_PAGE, error=error)

@app.route("/logout")
def logout():
    log_access("🚪LOGOUT")
    resp = make_response(redirect("/login"))
    resp.delete_cookie("auth_token")
    return resp

# ================================================================
#  ROUTES — PAGES
# ================================================================

@app.route("/")
@auth_required
def index():
    log_access("📄PAGE_VIEW")
    targets_json = json.dumps([
        {"id": t["id"], "name": t["name"]} for t in TARGETS
    ])
    return render_template_string(
        DASHBOARD_PAGE,
        version=__version__,
        targets_json=targets_json)

# ================================================================
#  ROUTES — STATUS API
# ================================================================

@app.route("/api/status")
@auth_required
def api_status():
    tid = request.args.get("target", "main")
    with state_lock:
        st = pc_states.get(tid)
        if not st:
            return jsonify({"error": "Unknown target"}), 404
        return jsonify({
            "name":       st["name"],
            "online":     st["online"],
            "ping_ms":    st["ping_ms"],
            "last_check": st["last_check"],
            "wol_count":  st["wol_count"],
            "history":    st["history"][-80:],
        })

@app.route("/api/sysinfo")
@auth_required
def api_sysinfo():
    return jsonify({
        "version": __version__,
        "python":  sys.version.split()[0],
        "uptime":  _uptime(),
        "mem":     _mem(),
        "db":      _dbsize(),
        "bind":    f"{C.BIND}:{C.PORT}",
        "targets": len(TARGETS),
        "pid":     os.getpid(),
    })

# ================================================================
#  ROUTES — WOL API
# ================================================================

def _wol_action(tid, repeat, label):
    with state_lock:
        st = pc_states.get(tid)
        if not st:
            return jsonify({"error": "Unknown target"}), 404
        now = time.time()
        if now - st["last_wol"] < C.COOLDOWN:
            r = int(C.COOLDOWN - (now - st["last_wol"]))
            return jsonify({
                "message": f"⏳ Cooldown {r}s"
            }), 429

    cnt = 0
    for _ in range(repeat):
        cnt += send_wol(st["mac"], repeat=3)
        time.sleep(0.05)

    with state_lock:
        st["last_wol"] = time.time()
        st["wol_count"] += cnt

    log_access(f"📡{label}", f"{cnt}pkts→{st['name']}")
    return jsonify({
        "message": f"✅ {label}: {cnt} packets → {st['name']}"
    })

@app.route("/api/wol")
@auth_required
def api_wol():
    tid = request.args.get("target", "main")
    return _wol_action(tid, 1, "WOL")

@app.route("/api/combo")
@auth_required
def api_combo():
    tid = request.args.get("target", "main")
    return _wol_action(tid, 2, "COMBO")

@app.route("/api/force")
@auth_required
def api_force():
    tid = request.args.get("target", "main")
    return _wol_action(tid, 10, "FORCE")

@app.route("/api/superforce")
@auth_required
def api_superforce():
    tid = request.args.get("target", "main")
    return _wol_action(tid, 30, "SUPERFORCE")

# ================================================================
#  ROUTES — SCHEDULE
# ================================================================

@app.route("/api/schedule")
@auth_required
def api_sched_set():
    m = request.args.get("minutes", type=int)
    tid = request.args.get("target", "main")
    if not m or m < 1 or m > 1440:
        return jsonify({"message": "1-1440 min"}), 400
    ip = request.headers.get(
        "X-Forwarded-For", request.remote_addr)
    with sched_lock:
        scheduled["active"] = True
        scheduled["ts"] = time.time() + m * 60
        scheduled["target"] = tid
        scheduled["by"] = ip
    log_access("⏰SCHED_SET", f"{m}min→{tid}")
    return jsonify({"message": f"⏰ Set: {m}min"})

@app.route("/api/schedule/cancel")
@auth_required
def api_sched_cancel():
    with sched_lock:
        was = scheduled["active"]
        scheduled["active"] = False
    log_access("⏰SCHED_CANCEL")
    return jsonify({
        "message": "⏰ Cancelled" if was else "Nothing active"
    })

@app.route("/api/schedule/status")
@auth_required
def api_sched_status():
    with sched_lock:
        return jsonify({
            "active": scheduled["active"],
            "ts":     scheduled["ts"],
            "target": scheduled["target"],
            "by":     scheduled["by"],
        })

# ================================================================
#  ROUTES — LOGS
# ================================================================

@app.route("/api/logs")
@auth_required
def api_logs():
    n = min(request.args.get("n", 60, type=int), 300)
    try:
        db = get_db()
        rows = db.execute(
            "SELECT ts,ip,device,action,detail "
            "FROM access_log ORDER BY id DESC LIMIT ?",
            (n,)).fetchall()
        total = db.execute(
            "SELECT COUNT(*) FROM access_log"
        ).fetchone()[0]
        db.close()
        return jsonify({
            "logs": [dict(r) for r in rows],
            "total": total
        })
    except:
        return jsonify({"logs": [], "total": 0})

@app.route("/api/logs/export")
@auth_required
def api_logs_export():
    log_access("📥LOG_EXPORT")
    db = get_db()
    rows = db.execute(
        "SELECT ts,ip,device,ua,action,detail,key_hint "
        "FROM access_log ORDER BY id DESC"
    ).fetchall()
    db.close()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "ip", "device", "user_agent",
                "action", "detail", "key_hint"])
    for r in rows:
        w.writerow([r["ts"], r["ip"], r["device"],
                     r["ua"], r["action"], r["detail"],
                     r["key_hint"]])

    resp = Response(buf.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = \
        f"attachment; filename=homesystem_logs_{datetime.now():%Y%m%d}.csv"
    return resp

# ================================================================
#  ROUTES — UPDATE / HEALTH
# ================================================================

@app.route("/api/check_update")
@auth_required
def api_check_update():
    remote = _remote_ver()
    return jsonify({
        "current": __version__,
        "remote": remote,
        "update_available": (
            remote is not None and remote != __version__
        )
    })

@app.route("/health")
def health():
    return jsonify({"status": "ok", "v": __version__})

# ================================================================
#  ROUTES — ADMIN
# ================================================================

@app.route("/admin/update")
@admin_required
def admin_update():
    if not C.UPDATE_URL:
        return jsonify({"message": "❌ UPDATE_URL not set"}), 400
    log_access("🔄ADMIN_UPDATE")
    try:
        bak = os.path.abspath(__file__) + ".bak"
        shutil.copy2(os.path.abspath(__file__), bak)
        with urllib.request.urlopen(
                C.UPDATE_URL, timeout=30) as r:
            code = r.read()
        if b"__version__" not in code:
            return jsonify({
                "message": "❌ Invalid file downloaded"
            }), 400
        with open(os.path.abspath(__file__), "wb") as f:
            f.write(code)
        def _r():
            time.sleep(2)
            os.execv(sys.executable,
                     [sys.executable] + sys.argv)
        threading.Thread(target=_r, daemon=True).start()
        return jsonify({
            "message": "✅ Updated, restarting...",
            "detail": f"Backup: {bak}"
        })
    except Exception as e:
        return jsonify({"message": f"❌ {e}"}), 500

@app.route("/admin/rollback")
@admin_required
def admin_rollback():
    bak = os.path.abspath(__file__) + ".bak"
    if not os.path.exists(bak):
        return jsonify({"message": "❌ No backup found"}), 404
    try:
        shutil.copy2(bak, os.path.abspath(__file__))
        log_access("⏪ROLLBACK")
        def _r():
            time.sleep(2)
            os.execv(sys.executable,
                     [sys.executable] + sys.argv)
        threading.Thread(target=_r, daemon=True).start()
        return jsonify({"message": "⏪ Rolled back, restarting..."})
    except Exception as e:
        return jsonify({"message": f"❌ {e}"}), 500

@app.route("/admin/restart")
@admin_required
def admin_restart():
    log_access("🔁RESTART")
    def _r():
        time.sleep(1.5)
        os.execv(sys.executable,
                 [sys.executable] + sys.argv)
    threading.Thread(target=_r, daemon=True).start()
    return jsonify({"message": "🔁 Restarting..."})

@app.route("/admin/logs/clear")
@admin_required
def admin_clear():
    db = get_db()
    db.execute("DELETE FROM access_log")
    db.execute("DELETE FROM events")
    db.commit()
    db.close()
    log_access("🧹CLEAR_LOGS")
    return jsonify({"message": "🧹 Cleared"})

# ================================================================
#  MAIN
# ================================================================

if __name__ == "__main__":
    print()
    print("╔═════════════════════════════════════════╗")
    print(f"║  HomeSystem v{__version__:>10s}                  ║")
    print("║  SSH-First · Zero-Leak · Multi-Target   ║")
    print("╚═════════════════════════════════════════╝")
    print()

    init_db()
    print(f"  [DB]    ✅ {DB_PATH}")

    for t in TARGETS:
        print(f"  [TGT]   📌 {t['name']} → {t['ip']}")

    threading.Thread(target=_monitor, daemon=True).start()
    print(f"  [MON]   ✅ Pinging every {C.PING_INT}s")

    threading.Thread(target=_scheduler, daemon=True).start()
    print("  [SCHED] ✅ Timer thread")

    if C.TG_TOKEN:
        print("  [TG]    ✅ Telegram notifications")

    print(f"  [BIND]  🔒 {C.BIND}:{C.PORT}")

    if C.BIND == "127.0.0.1":
        print()
        print("  ⚠️  SSH TUNNEL REQUIRED:")
        print("  ssh -L 8080:127.0.0.1:8080 \\")
        print("      -p 8022 <phone_ip>")
        print()
        print("  Then open:")
        print(f"  http://localhost:{C.PORT}/?key=<secret>")
    else:
        print()
        print("  📱 Direct access:")
        print(f"  http://<phone_ip>:{C.PORT}/?key=<secret>")

    print()
    print("=" * 43)

    app.run(
        host=C.BIND,
        port=C.PORT,
        debug=False,
        threaded=True
    )
