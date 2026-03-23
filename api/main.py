"""
NAC Policy Engine — FastAPI
FreeRADIUS'ın rlm_rest modülü üzerinden çağırdığı policy engine.

Endpoint özeti:
  POST /auth            → Kullanıcı doğrulama + rate-limiting
  POST /authorize       → VLAN/policy atribütleri (rlm_rest authorize)
  POST /accounting      → Oturum verisi kaydet (rlm_rest accounting)
  GET  /users           → Kullanıcı listesi ve durum
  GET  /sessions/active → Redis'teki aktif oturumlar
  GET  /health          → Servis sağlığı (healthcheck için)
"""

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone

import asyncpg
import bcrypt
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI(title="NAC Policy Engine", version="1.0.0")

# ---- Konfigürasyon ----
DB_URL          = os.getenv("DATABASE_URL", "postgresql://radius:radius@postgres:5432/radius")
REDIS_URL       = os.getenv("REDIS_URL", "redis://redis:6379")
RATE_LIMIT_MAX  = int(os.getenv("RATE_LIMIT_MAX", "5"))
RATE_LIMIT_WIN  = int(os.getenv("RATE_LIMIT_WINDOW", "300"))  # saniye

# Grup → VLAN eşlemesi
VLAN_MAP = {
    "admin":    "10",
    "employee": "20",
    "guest":    "30",
}

# ---- Global bağlantı nesneleri ----
db_pool: asyncpg.Pool   = None
redis_cli: aioredis.Redis = None


# Uygulama yaşam döngüsü

@app.on_event("startup")
async def startup():
    global db_pool, redis_cli
    db_pool   = await asyncpg.create_pool(DB_URL, min_size=2, max_size=10)
    redis_cli = await aioredis.from_url(REDIS_URL, decode_responses=True)


@app.on_event("shutdown")
async def shutdown():
    await db_pool.close()
    await redis_cli.aclose()


# Yardımcı fonksiyonlar

def extract(body: dict, attr: str, default=None):
    """
    FreeRADIUS rlm_rest JSON formatından atribüt değeri çıkarır.

    FreeRADIUS 3.x rlm_rest iki farklı format gönderebilir:
      Format A (list): {"User-Name": [{"type": "string", "value": "alice"}]}
      Format B (dict): {"User-Name": {"type": "string", "value": ["alice"]}}

    Direkt API testi için fallback:
      {"username": "alice"}
    """
    if attr in body:
        item = body[attr]
        # Format A: değer liste içinde
        if isinstance(item, list) and item:
            val = item[0].get("value", default) if isinstance(item[0], dict) else item[0]
        # Format B: değer doğrudan dict
        elif isinstance(item, dict):
            val = item.get("value", default)
        else:
            val = item
        # value kendisi liste olabilir: ["alice"] → "alice"
        if isinstance(val, list):
            return val[0] if val else default
        return val
    # Direkt çağrı için fallback (snake_case ve orijinal key)
    snake = attr.lower().replace("-", "_")
    return body.get(snake, body.get(attr, default))


def verify_password(plaintext: str, attribute: str, stored: str) -> bool:
    """Atribüt tipine göre şifre doğrulaması yapar."""
    if attribute == "Cleartext-Password":
        return plaintext == stored
    elif attribute == "MD5-Password":
        # PostgreSQL md5() ile aynı formatta: lowercase hex
        return hashlib.md5(plaintext.encode()).hexdigest() == stored
    elif attribute == "Crypt-Password":
        # bcrypt — API üzerinden oluşturulan kullanıcılar için
        return bcrypt.checkpw(plaintext.encode(), stored.encode())
    return False


def is_mac(value: str) -> bool:
    """MAC adresi formatını tespit et (MAB istekleri için)."""
    return bool(re.match(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$", value))


async def rate_limit_increment(key: str):
    """Başarısız deneme sayacını artır."""
    await redis_cli.incr(key)
    await redis_cli.expire(key, RATE_LIMIT_WIN)


# Endpoint: /health

@app.get("/health")
async def health():
    checks = {"api": "ok", "db": "error", "redis": "error"}
    try:
        async with db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        checks["db"] = "ok"
    except Exception:
        pass
    try:
        await redis_cli.ping()
        checks["redis"] = "ok"
    except Exception:
        pass

    overall = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
    status_code = 200 if overall == "ok" else 503
    return Response(
        content=json.dumps({"status": overall, **checks}),
        media_type="application/json",
        status_code=status_code,
    )


# Endpoint: POST /auth
# Kullanıcı doğrulama + Redis rate-limiting
# FreeRADIUS'ın authenticate aşamasında veya direkt curl ile çağrılır.

@app.post("/auth")
async def auth(body: dict):
    username = extract(body, "User-Name") or body.get("username")
    password = extract(body, "User-Password") or body.get("password")

    if not username or not password:
        raise HTTPException(status_code=400, detail="username ve password zorunlu")

    # ---- Rate limiting (Redis) ----
    rl_key   = f"rl:{username}"
    attempts = await redis_cli.get(rl_key)
    if attempts and int(attempts) >= RATE_LIMIT_MAX:
        ttl = await redis_cli.ttl(rl_key)
        # HTTP 401 → FreeRADIUS rlm_rest bunu REJECT olarak yorumlar
        raise HTTPException(status_code=401,
                            detail=f"Rate limited. {ttl}s sonra tekrar dene.")

    # ---- Veritabanından kullanıcıyı getir ----
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT attribute, value FROM radcheck
            WHERE username = $1
              AND attribute IN ('Cleartext-Password', 'MD5-Password', 'Crypt-Password')
            """,
            username,
        )

    if not row:
        await rate_limit_increment(rl_key)
        raise HTTPException(status_code=401, detail="Kullanıcı bulunamadı")

    # ---- Şifre doğrulama ----
    if verify_password(password, row["attribute"], row["value"]):
        await redis_cli.delete(rl_key)  # başarılı girişte sayacı sıfırla
        # HTTP 200 → FreeRADIUS rlm_rest bunu ACCEPT olarak yorumlar
        return {"code": 2, "message": "Access-Accept"}
    else:
        await rate_limit_increment(rl_key)
        raise HTTPException(status_code=401, detail="Hatalı şifre")


# Endpoint: POST /authorize
# FreeRADIUS authorize aşamasında rlm_rest tarafından çağrılır.
# VLAN atribütlerini döner. MAB (MAC auth) desteği dahil.

@app.post("/authorize")
async def authorize(body: dict):
    logger.debug("AUTHORIZE IN: %s", json.dumps(body, default=str))
    username = extract(body, "User-Name") or body.get("username")
    if not username:
        return {}

    # ---- Kullanıcının grubunu bul ----
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT groupname FROM radusergroup WHERE username = $1 ORDER BY priority LIMIT 1",
            username,
        )

    mab_request = is_mac(username)

    if not row:
        if mab_request:
            # Bilinmeyen MAC → guest VLAN (PDF: "reject veya guest VLAN" — biz guest seçiyoruz)
            vlan = VLAN_MAP["guest"]
        else:
            return {}  # normal kullanıcı ama grubu yok
    else:
        vlan = VLAN_MAP.get(row["groupname"], VLAN_MAP["guest"])

    # Şifre hash'ini al — FreeRADIUS PAP modülü bunu control listesiyle doğrular
    async with db_pool.acquire() as conn:
        pwd_row = await conn.fetchrow(
            """
            SELECT attribute, value FROM radcheck
            WHERE username = $1
              AND attribute IN ('Cleartext-Password', 'MD5-Password', 'Crypt-Password')
            """,
            username,
        )

    # ---- FreeRADIUS rlm_rest RESPONSE formatı ----
    # Önemli: nested dict/list değil, düz "list:Attr": "değer" formatı
    # "control:Attr" → FreeRADIUS iç listesi (şifre kontrolü için)
    # "reply:Attr"   → Access-Accept paketine eklenir (VLAN)
    response = {
        "reply:Tunnel-Type":             "13",  # 13 = VLAN
        "reply:Tunnel-Medium-Type":      "6",   # 6 = IEEE-802
        "reply:Tunnel-Private-Group-Id": vlan,
    }

    if pwd_row:
        # Bilinen kullanıcı: DB'deki hash ile PAP doğrulaması
        response[f"control:{pwd_row['attribute']}"] = pwd_row["value"]
    elif mab_request:
        # Bilinmeyen MAC: MAB convention'ı gereği User-Password = MAC adresi
        # Cleartext-Password olarak MAC'i set et → PAP doğrulayabilir
        response["control:Cleartext-Password"] = username

    logger.debug("AUTHORIZE OUT: %s", json.dumps(response, default=str))
    return response


# Endpoint: POST /accounting
# FreeRADIUS accounting aşamasında rlm_rest tarafından çağrılır.
# Start/Interim-Update/Stop paketlerini işler.

@app.post("/accounting")
async def accounting(body: dict):
    username       = extract(body, "User-Name",          "unknown")
    session_id     = extract(body, "Acct-Session-Id",    "")
    status_type    = extract(body, "Acct-Status-Type",   "")
    nas_ip         = extract(body, "NAS-IP-Address",     "")
    session_time   = int(extract(body, "Acct-Session-Time",    0) or 0)
    input_octets   = int(extract(body, "Acct-Input-Octets",    0) or 0)
    output_octets  = int(extract(body, "Acct-Output-Octets",   0) or 0)

    now = datetime.now(timezone.utc)

    async with db_pool.acquire() as conn:

        if status_type in ("Start", "1"):
            # Yeni oturum başladı → DB'ye yaz, Redis'e cache'le
            await conn.execute(
                """
                INSERT INTO radacct
                    (acctsessionid, username, nasipaddress, acctstarttime, acctstatustype)
                VALUES ($1, $2, $3, $4, 'Start')
                ON CONFLICT (acctsessionid) DO NOTHING
                """,
                session_id, username, nas_ip, now,
            )
            # Redis: 24 saat TTL ile aktif oturum cache'i
            session_data = {
                "session_id": session_id,
                "username":   username,
                "nas_ip":     nas_ip,
                "start":      now.isoformat(),
            }
            await redis_cli.setex(f"session:{session_id}", 86400, json.dumps(session_data))
            await redis_cli.sadd("active_sessions", session_id)

        elif status_type in ("Interim-Update", "3"):
            # Oturum devam ediyor → istatistikleri güncelle
            await conn.execute(
                """
                UPDATE radacct
                SET acctsessiontime  = $1,
                    acctinputoctets  = $2,
                    acctoutputoctets = $3,
                    acctstatustype   = 'Interim-Update',
                    acctupdatetime   = $4
                WHERE acctsessionid = $5
                """,
                session_time, input_octets, output_octets, now, session_id,
            )

        elif status_type in ("Stop", "2"):
            # Oturum bitti → DB'yi kapat, Redis'ten sil
            await conn.execute(
                """
                UPDATE radacct
                SET acctstoptime     = $1,
                    acctsessiontime  = $2,
                    acctinputoctets  = $3,
                    acctoutputoctets = $4,
                    acctstatustype   = 'Stop'
                WHERE acctsessionid = $5
                """,
                now, session_time, input_octets, output_octets, session_id,
            )
            await redis_cli.delete(f"session:{session_id}")
            await redis_cli.srem("active_sessions", session_id)

    return {"status": "ok"}


# Endpoint: GET /users
# Kullanıcı listesi, grup bilgisi ve aktif oturum sayısı

@app.get("/users")
async def users():
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                rc.username,
                rug.groupname,
                COUNT(ra.radacctid) FILTER (WHERE ra.acctstatustype != 'Stop') AS active_sessions
            FROM radcheck rc
            LEFT JOIN radusergroup rug ON rc.username = rug.username
            LEFT JOIN radacct ra       ON rc.username = ra.username
            WHERE rc.attribute IN ('Cleartext-Password', 'MD5-Password', 'Crypt-Password')
            GROUP BY rc.username, rug.groupname
            ORDER BY rc.username
            """
        )
    return [
        {
            "username":        r["username"],
            "group":           r["groupname"],
            "active_sessions": r["active_sessions"] or 0,
        }
        for r in rows
    ]


# Endpoint: GET /sessions/active
# Redis'teki aktif oturumları döner (hızlı sorgulama)

@app.get("/sessions/active")
async def sessions_active():
    session_ids = await redis_cli.smembers("active_sessions")
    sessions = []
    for sid in session_ids:
        data = await redis_cli.get(f"session:{sid}")
        if data:
            sessions.append(json.loads(data))

    return {"count": len(sessions), "sessions": sessions}


# Endpoint: GET /dashboard
# Tarayıcı tabanlı test ve izleme arayüzü

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(content="""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NAC System</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: Arial, sans-serif;
    font-size: 13px;
    background: #ececec;
    color: #222;
  }

  #topbar {
    background: #3a6ea5;
    color: #fff;
    padding: 8px 16px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  #topbar h1 { font-size: 14px; font-weight: bold; }
  #topbar span { font-size: 12px; color: #ccdff5; }

  #wrap { padding: 16px; display: flex; flex-direction: column; gap: 12px; }

  .infobar {
    background: #fff;
    border: 1px solid #bbb;
    padding: 8px 12px;
    display: flex;
    gap: 32px;
    align-items: center;
  }

  .infobar-item { display: flex; flex-direction: column; }
  .infobar-item .label { font-size: 11px; color: #666; }
  .infobar-item .value { font-size: 13px; font-weight: bold; margin-top: 1px; }

  .status-ok  { color: #1a7a1a; }
  .status-err { color: #aa1111; }

  .section {
    background: #fff;
    border: 1px solid #bbb;
  }

  .section-head {
    background: #d8e4f0;
    border-bottom: 1px solid #bbb;
    padding: 5px 10px;
    font-weight: bold;
    font-size: 12px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .section-body { padding: 10px; }

  .cols { display: flex; gap: 12px; flex-wrap: wrap; }
  .col-wide { flex: 2; min-width: 300px; }
  .col-narrow { flex: 1; min-width: 240px; }

  table { width: 100%; border-collapse: collapse; font-size: 12px; }

  thead th {
    background: #eef2f7;
    border: 1px solid #ccc;
    padding: 5px 8px;
    text-align: left;
    font-weight: bold;
  }

  tbody td {
    border: 1px solid #ddd;
    padding: 5px 8px;
    vertical-align: middle;
  }

  tbody tr:nth-child(even) td { background: #f7f9fc; }
  tbody tr:hover td { background: #eaf1fb; }

  .field-group { margin-bottom: 8px; }

  .field-group label {
    display: block;
    font-size: 12px;
    margin-bottom: 3px;
    font-weight: bold;
    color: #333;
  }

  .field-group input {
    width: 100%;
    padding: 5px 7px;
    border: 1px solid #bbb;
    font-size: 12px;
    background: #fff;
    color: #222;
  }

  .field-group input:focus { outline: 1px solid #3a6ea5; border-color: #3a6ea5; }

  .btn-row { display: flex; gap: 6px; margin-top: 8px; }

  button {
    padding: 5px 14px;
    font-size: 12px;
    cursor: pointer;
    border: 1px solid;
  }

  .btn-main { background: #3a6ea5; color: #fff; border-color: #2c5688; }
  .btn-main:hover { background: #2c5688; }

  .btn-plain { background: #e8e8e8; color: #333; border-color: #aaa; }
  .btn-plain:hover { background: #d8d8d8; }

  .btn-small {
    font-size: 11px;
    padding: 2px 8px;
    background: #e8e8e8;
    color: #333;
    border: 1px solid #aaa;
    cursor: pointer;
  }
  .btn-small:hover { background: #d0d0d0; }

  .msg { margin-top: 8px; padding: 6px 10px; font-size: 12px; border: 1px solid; display: none; }
  .msg-ok   { background: #eafaea; border-color: #5caa5c; color: #1a4d1a; }
  .msg-fail { background: #faeaea; border-color: #c05050; color: #5c1a1a; }
  .msg-info { background: #eaf0fa; border-color: #5080c0; color: #1a3060; }

  .empty { color: #888; font-style: italic; padding: 4px 0; }

  .divider { border: none; border-top: 1px solid #ddd; margin: 10px 0; }

  code { font-family: Consolas, monospace; font-size: 11px; }
</style>
</head>
<body>

<div id="topbar">
  <h1>NAC System &mdash; Policy Engine</h1>
  <span id="last-update"></span>
</div>

<div id="wrap">

  <div class="infobar">
    <div class="infobar-item">
      <span class="label">API Durumu</span>
      <span class="value" id="api-status">kontrol ediliyor...</span>
    </div>
    <div class="infobar-item">
      <span class="label">Aktif Oturum</span>
      <span class="value" id="session-count">—</span>
    </div>
    <div class="infobar-item">
      <span class="label">Kayitli Kullanici</span>
      <span class="value" id="user-count">—</span>
    </div>
  </div>

  <div class="cols">

    <div class="col-wide">
      <div class="section">
        <div class="section-head">
          Kullanici Listesi
          <button class="btn-small" onclick="loadUsers()">Yenile</button>
        </div>
        <div class="section-body">
          <div id="users-table"><p class="empty">Yukleniyor...</p></div>
        </div>
      </div>
    </div>

    <div class="col-narrow">
      <div class="section">
        <div class="section-head">Kimlik Dogrulama Testi</div>
        <div class="section-body">
          <div class="field-group">
            <label>Kullanici Adi</label>
            <input type="text" id="auth-user" placeholder="admin" />
          </div>
          <div class="field-group">
            <label>Sifre</label>
            <input type="password" id="auth-pass" placeholder="admin123" />
          </div>
          <div class="btn-row">
            <button class="btn-main"  onclick="testAuth()">Test Et</button>
            <button class="btn-plain" onclick="clearAuth()">Temizle</button>
          </div>
          <div class="msg" id="auth-result"></div>

          <hr class="divider">

          <div class="field-group">
            <label>MAB &mdash; MAC Adresi</label>
            <input type="text" id="mac-input" placeholder="aa:bb:cc:dd:ee:ff" />
          </div>
          <div class="btn-row">
            <button class="btn-main" onclick="testMAB()">Test Et</button>
          </div>
          <div class="msg" id="mab-result"></div>
        </div>
      </div>
    </div>

  </div>

  <div class="section">
    <div class="section-head">
      Aktif Oturumlar (Redis)
      <button class="btn-small" onclick="loadSessions()">Yenile</button>
    </div>
    <div class="section-body">
      <div id="sessions-table"><p class="empty">Yukleniyor...</p></div>
    </div>
  </div>

</div>

<script>
const VLAN_LABELS = { "10": "Admin", "20": "Employee", "30": "Guest" };
const VLAN_MAP    = { admin: "10", employee: "20", guest: "30" };

async function apiFetch(path, opts) {
  try {
    const response = await fetch(path, opts);
    const data = await response.json();
    return { ok: response.ok, status: response.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: { detail: e.message } };
  }
}

async function checkHealth() {
  const result = await apiFetch("/health");
  const el = document.getElementById("api-status");
  if (result.ok) {
    el.innerHTML = '<span class="status-ok">Calisiyor</span>';
  } else {
    el.innerHTML = '<span class="status-err">Erisim hatasi</span>';
  }
}

async function loadUsers() {
  const result = await apiFetch("/users");
  const el  = document.getElementById("users-table");
  const cnt = document.getElementById("user-count");

  if (!result.ok || !result.data.length) {
    el.innerHTML = '<p class="empty-note">Kullanici bulunamadi.</p>';
    return;
  }

  cnt.textContent = result.data.length;

  const rows = result.data.map(function(u) {
    const group = u.group || "—";
    const vlan  = VLAN_MAP[group] || "—";

    const groupTag = group;
    const vlanTag  = vlan !== "—" ? "VLAN " + vlan : "—";

    const sessions = u.active_sessions > 0
      ? '<strong>' + u.active_sessions + '</strong>'
      : '0';

    return "<tr><td>" + u.username + "</td><td>" + groupTag + "</td><td>" + vlanTag + "</td><td>" + sessions + "</td></tr>";
  }).join("");

  el.innerHTML = "<table><thead><tr><th>Kullanici</th><th>Grup</th><th>VLAN</th><th>Aktif Oturum</th></tr></thead><tbody>" + rows + "</tbody></table>";
}

async function loadSessions() {
  const result = await apiFetch("/sessions/active");
  const el  = document.getElementById("sessions-table");
  const cnt = document.getElementById("session-count");

  cnt.textContent = (result.data && result.data.count !== undefined) ? result.data.count : "—";

  if (!result.data || !result.data.sessions || !result.data.sessions.length) {
    el.innerHTML = '<p class="empty-note">Aktif oturum yok.</p>';
    return;
  }

  const rows = result.data.sessions.map(function(s) {
    const start = s.start ? new Date(s.start).toLocaleString("tr-TR") : "—";
    return "<tr><td><code>" + s.session_id + "</code></td><td>" + s.username + "</td><td>" + (s.nas_ip || "—") + "</td><td>" + start + "</td></tr>";
  }).join("");

  el.innerHTML = "<table><thead><tr><th>Oturum ID</th><th>Kullanici</th><th>NAS IP</th><th>Baslangic</th></tr></thead><tbody>" + rows + "</tbody></table>";
}

async function testAuth() {
  const username = document.getElementById("auth-user").value.trim();
  const password = document.getElementById("auth-pass").value.trim();
  const el = document.getElementById("auth-result");

  if (!username || !password) {
    showResult(el, "fail", "Kullanici adi ve sifre gerekli.");
    return;
  }

  const result = await apiFetch("/auth", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: username, password: password })
  });

  if (result.ok) {
    showResult(el, "ok", "Access-Accept — kimlik dogrulandi.");
  } else {
    const msg = (result.data && result.data.detail) ? result.data.detail : "Bilinmeyen hata";
    showResult(el, "fail", "Access-Reject — " + msg);
  }

  loadUsers();
  loadSessions();
}

async function testMAB() {
  const mac = document.getElementById("mac-input").value.trim();
  const el  = document.getElementById("mab-result");

  if (!mac) {
    showResult(el, "fail", "MAC adresi girin.");
    return;
  }

  const result = await apiFetch("/authorize", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ "User-Name": mac, "User-Password": mac })
  });

  if (result.ok && result.data["reply:Tunnel-Private-Group-Id"]) {
    const vlan  = result.data["reply:Tunnel-Private-Group-Id"];
    const label = VLAN_LABELS[vlan] || vlan;
    showResult(el, "ok", "Kabul edildi — VLAN " + vlan + " (" + label + ")");
  } else if (result.ok && Object.keys(result.data).length === 0) {
    showResult(el, "fail", "Reddedildi — MAC tanimli degil, yeterli politika yok.");
  } else {
    showResult(el, "info", "Yanit: " + JSON.stringify(result.data));
  }
}

function clearAuth() {
  document.getElementById("auth-user").value = "";
  document.getElementById("auth-pass").value = "";
  const el = document.getElementById("auth-result");
  el.style.display = "none";
  el.className = "msg";
}

function showResult(el, type, message) {
  el.className = "msg msg-" + type;
  el.textContent = message;
  el.style.display = "block";
}

function updateTimestamp() {
  document.getElementById("last-update").textContent =
    "Son guncelleme: " + new Date().toLocaleTimeString("tr-TR");
}

async function refreshAll() {
  await Promise.all([checkHealth(), loadUsers(), loadSessions()]);
  updateTimestamp();
}

refreshAll();
setInterval(refreshAll, 10000);
</script>

</body>
</html>""")
