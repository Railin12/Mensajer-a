"""
Nexo - acceso por token o huella. Chat privado + IA (proximamente).
"""
from __future__ import annotations
import asyncio, base64, hashlib, hmac, json, logging, os, re, secrets, time, uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, Optional, Set

import asyncpg, uvicorn
from fastapi import (FastAPI, Form, HTTPException, Request, Response,
                     WebSocket, WebSocketDisconnect)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from webauthn import (
    generate_registration_options, verify_registration_response,
    generate_authentication_options, verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria, UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

try:
    from pywebpush import webpush, WebPushException
    HAS_WEBPUSH = True
except ImportError:
    HAS_WEBPUSH = False
    log_dummy = None

SESSION_TTL  = 60 * 60 * 8
MAX_TEXT_LEN = 4000
USE_HTTPS    = os.getenv("USE_HTTPS", "0") == "1"

WEBAUTHN_RP_ID   = os.getenv("WEBAUTHN_RP_ID",   "localhost")
WEBAUTHN_RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "App")
WEBAUTHN_ORIGIN  = os.getenv("WEBAUTHN_ORIGIN",  "http://localhost:8000")

VAPID_PUBLIC  = os.getenv("VAPID_PUBLIC_KEY",  "")
VAPID_PRIVATE = os.getenv("VAPID_PRIVATE_KEY", "")
VAPID_SUBJECT = os.getenv("VAPID_SUBJECT", "mailto:admin@example.com")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("app")

# ─── Password hashing ────────────────────────────────────────────────
SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN = 2**14, 8, 1, 32

def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    key = hashlib.scrypt(pw.encode(), salt=salt,
                         n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(key).decode()

def verify_password(pw: str, stored: str) -> bool:
    try:
        s, k = stored.split("$", 1)
        salt = base64.b64decode(s); expected = base64.b64decode(k)
        key = hashlib.scrypt(pw.encode(), salt=salt,
                             n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)
        return hmac.compare_digest(key, expected)
    except Exception:
        return False

def load_users():
    users = {}
    for L in ("A", "B"):
        n   = os.getenv(f"USER_{L}_NAME", "").strip()
        p   = os.getenv(f"USER_{L}_PASSWORD", "")
        pin = os.getenv(f"USER_{L}_PIN", "")
        if n and p:
            users[n] = {"hash": hash_password(p), "pin": pin}
    return users

USERS = load_users()
log.info(f"usuarios: {list(USERS.keys())}")

def get_peer(u: str) -> Optional[str]:
    for x in USERS:
        if x != u: return x
    return None

# ─── Estado ──────────────────────────────────────────────────────────
SESSIONS:    Dict[str, dict]             = {}
CONNECTIONS: Dict[str, Set[WebSocket]]   = {}
CHALLENGES:  Dict[str, bytes]            = {}
pool: Optional[asyncpg.Pool]             = None

def is_online(u): return bool(CONNECTIONS.get(u))

async def send_to(u, payload):
    conns = CONNECTIONS.get(u)
    if not conns: return
    dead = []
    for ws in list(conns):
        try: await ws.send_json(payload)
        except Exception: dead.append(ws)
    for ws in dead: conns.discard(ws)

# ─── Neon ────────────────────────────────────────────────────────────
async def init_db():
    raw = os.getenv("DATABASE_URL", "")
    if not raw:
        raise RuntimeError("Falta DATABASE_URL")
    clean = raw.replace("&channel_binding=require", "").replace("channel_binding=require", "")
    for i in range(1, 6):
        try:
            p = await asyncpg.create_pool(clean, min_size=1, max_size=3,
                                          timeout=60, command_timeout=60,
                                          statement_cache_size=0)
            async with p.acquire() as c:
                await c.execute("""
                    CREATE TABLE IF NOT EXISTS messages (
                        id TEXT PRIMARY KEY,
                        sender TEXT NOT NULL,
                        receiver TEXT NOT NULL,
                        text TEXT NOT NULL,
                        created_at BIGINT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'sent',
                        reply_to TEXT
                    );""")
                await c.execute("CREATE INDEX IF NOT EXISTS idx_msg_sender   ON messages(sender)")
                await c.execute("CREATE INDEX IF NOT EXISTS idx_msg_receiver ON messages(receiver)")
                await c.execute("""
                    CREATE TABLE IF NOT EXISTS webauthn_credentials (
                        credential_id TEXT PRIMARY KEY,
                        username TEXT NOT NULL,
                        public_key TEXT NOT NULL,
                        sign_count BIGINT NOT NULL DEFAULT 0,
                        kind TEXT NOT NULL DEFAULT 'chat',
                        created_at BIGINT NOT NULL
                    );""")
                await c.execute("CREATE INDEX IF NOT EXISTS idx_wac_user ON webauthn_credentials(username)")
                await c.execute("""
                    CREATE TABLE IF NOT EXISTS access_tokens (
                        token TEXT PRIMARY KEY,
                        username TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        created_at BIGINT NOT NULL
                    );""")
                await c.execute("""
                    CREATE TABLE IF NOT EXISTS push_subscriptions (
                        id TEXT PRIMARY KEY,
                        username TEXT NOT NULL,
                        subscription TEXT NOT NULL,
                        created_at BIGINT NOT NULL
                    );""")
                await c.execute("CREATE INDEX IF NOT EXISTS idx_push_user ON push_subscriptions(username)")
            log.info("Neon OK")
            return p
        except Exception as e:
            log.warning(f"init_db {i}/5: {type(e).__name__}: {e}")
            await asyncio.sleep(2 * i)
    raise RuntimeError("Neon no conecta")

@asynccontextmanager
async def lifespan(app):
    global pool
    pool = await init_db()
    yield
    if pool: await pool.close()

app = FastAPI(lifespan=lifespan)
if Path("static").exists():
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.middleware("http")
async def no_cache(request, call_next):
    r = await call_next(request)
    if request.url.path == "/" or request.url.path.endswith(".html"):
        r.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        r.headers["Pragma"] = "no-cache"
    return r

# ─── Páginas ─────────────────────────────────────────────────────────
@app.get("/")
async def index():      return FileResponse("templates/index.html")
@app.get("/ia")
async def page_ia():    return FileResponse("templates/ia.html")
@app.get("/politicas")
async def page_pol():   return FileResponse("templates/politicas.html")
@app.get("/favicon.ico")
async def fav():        return Response(status_code=204)

# ─── API básica ──────────────────────────────────────────────────────
@app.get("/api/status")
async def api_status(): return {"ok": True, "users": list(USERS.keys())}

@app.get("/api/me")
async def api_me(request: Request):
    t = request.cookies.get("session")
    s = SESSIONS.get(t) if t else None
    if not s: return {"authenticated": False}
    u = s["username"]; p = get_peer(u)
    return {"authenticated": True, "username": u, "level": s["level"],
            "peer": p, "peer_online": is_online(p) if p else False}

@app.get("/api/config")
async def api_config():
    return {
        "vapid_public":  VAPID_PUBLIC,
        "push_enabled":  HAS_WEBPUSH and bool(VAPID_PUBLIC) and bool(VAPID_PRIVATE),
    }

# ─── Login tradicional (acceso con credenciales) ─────────────────────
@app.post("/api/login")
async def api_login(response: Response,
                    username: str = Form(...), password: str = Form(...)):
    u = username.strip()
    stored = USERS.get(u)
    if not (stored and verify_password(password, stored["hash"])):
        await asyncio.sleep(0.4)
        raise HTTPException(401, "Credenciales incorrectas")
    t = secrets.token_urlsafe(32)
    SESSIONS[t] = {"username": u, "level": 1, "created_at": time.time()}
    response.set_cookie("session", t, max_age=SESSION_TTL, httponly=True,
                        secure=USE_HTTPS, samesite="strict", path="/")
    return {"ok": True, "step": "pin"}

@app.post("/api/pin")
async def api_pin(request: Request, pin: str = Form(...)):
    t = request.cookies.get("session")
    s = SESSIONS.get(t) if t else None
    if not s: raise HTTPException(401, "Sesion invalida")
    exp = USERS.get(s["username"], {}).get("pin", "")
    if not secrets.compare_digest(exp, pin.strip()):
        await asyncio.sleep(0.4)
        raise HTTPException(401, "PIN incorrecto")
    s["level"] = 2
    return {"ok": True}

@app.post("/api/logout")
async def api_logout(request: Request, response: Response):
    t = request.cookies.get("session")
    if t: SESSIONS.pop(t, None)
    response.delete_cookie("session", path="/")
    return {"ok": True}

# ─── Tokens ──────────────────────────────────────────────────────────
@app.post("/api/token/login")
async def token_login(request: Request, response: Response, token: str = Form(...)):
    token = token.strip()
    row = await pool.fetchrow("SELECT * FROM access_tokens WHERE token = $1", token)
    if not row:
        await asyncio.sleep(0.4)
        raise HTTPException(401, "Token invalido")
    t = secrets.token_urlsafe(32)
    SESSIONS[t] = {"username": row["username"], "level": 2, "created_at": time.time()}
    response.set_cookie("session", t, max_age=SESSION_TTL, httponly=True,
                        secure=USE_HTTPS, samesite="strict", path="/")
    return {"ok": True, "kind": row["kind"], "username": row["username"]}

@app.post("/api/token/generate")
async def token_generate(request: Request):
    t = request.cookies.get("session")
    s = SESSIONS.get(t) if t else None
    if not s or s["level"] < 2: raise HTTPException(401, "Sesion invalida")
    body = await request.json()
    kind = (body.get("kind") or "chat").lower()
    if kind not in ("chat", "ia"): kind = "chat"
    u = s["username"]
    await pool.execute("DELETE FROM access_tokens WHERE username = $1", u)
    tok = secrets.token_urlsafe(24)
    await pool.execute(
        "INSERT INTO access_tokens (token, username, kind, created_at) VALUES ($1,$2,$3,$4)",
        tok, u, kind, int(time.time()))
    return {"ok": True, "token": tok, "kind": kind}

@app.post("/api/token/revoke")
async def token_revoke(request: Request):
    t = request.cookies.get("session")
    s = SESSIONS.get(t) if t else None
    if not s: raise HTTPException(401, "Sesion invalida")
    await pool.execute("DELETE FROM access_tokens WHERE username = $1", s["username"])
    return {"ok": True}

@app.get("/api/token/list")
async def token_list(request: Request):
    t = request.cookies.get("session")
    s = SESSIONS.get(t) if t else None
    if not s: raise HTTPException(401, "Sesion invalida")
    rows = await pool.fetch(
        "SELECT kind, created_at FROM access_tokens WHERE username = $1", s["username"])
    return {"tokens": [dict(r) for r in rows]}

# ─── WebAuthn ────────────────────────────────────────────────────────
def _sess_user(request):
    t = request.cookies.get("session")
    s = SESSIONS.get(t) if t else None
    return s["username"] if s else None

@app.post("/api/webauthn/register/begin")
async def wac_reg_begin(request: Request):
    u = _sess_user(request)
    if not u: raise HTTPException(401, "Sesion invalida")
    ex = await pool.fetch("SELECT credential_id FROM webauthn_credentials WHERE username = $1", u)
    excl = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"])) for r in ex]
    opts = generate_registration_options(
        rp_id=WEBAUTHN_RP_ID, rp_name=WEBAUTHN_RP_NAME,
        user_id=u.encode(), user_name=u, exclude_credentials=excl,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED))
    CHALLENGES["reg:" + u] = opts.challenge
    return Response(content=options_to_json(opts), media_type="application/json")

@app.post("/api/webauthn/register/finish")
async def wac_reg_finish(request: Request):
    u = _sess_user(request)
    if not u: raise HTTPException(401, "Sesion invalida")
    body = await request.json()
    exp = CHALLENGES.pop("reg:" + u, None)
    if not exp: raise HTTPException(400, "Challenge no encontrado")
    try:
        v = verify_registration_response(credential=body["credential"],
            expected_challenge=exp, expected_origin=WEBAUTHN_ORIGIN,
            expected_rp_id=WEBAUTHN_RP_ID, require_user_verification=False)
    except Exception as e:
        raise HTTPException(400, f"Registro: {e}")
    cid = bytes_to_base64url(v.credential_id)
    pk  = bytes_to_base64url(v.credential_public_key)
    kind = (body.get("kind") or "chat").lower()
    if kind not in ("chat", "ia"): kind = "chat"
    await pool.execute(
        "INSERT INTO webauthn_credentials "
        "(credential_id, username, public_key, sign_count, kind, created_at) "
        "VALUES ($1,$2,$3,$4,$5,$6) "
        "ON CONFLICT (credential_id) DO UPDATE SET kind = $5",
        cid, u, pk, v.sign_count, kind, int(time.time()))
    return {"ok": True, "kind": kind}

@app.post("/api/webauthn/login/begin")
async def wac_login_begin():
    rows = await pool.fetch("SELECT credential_id FROM webauthn_credentials")
    if not rows: raise HTTPException(404, "Sin credenciales")
    allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"])) for r in rows]
    opts = generate_authentication_options(rp_id=WEBAUTHN_RP_ID, allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED)
    CHALLENGES["login"] = opts.challenge
    return Response(content=options_to_json(opts), media_type="application/json")

@app.post("/api/webauthn/login/finish")
async def wac_login_finish(request: Request, response: Response):
    body = await request.json()
    exp = CHALLENGES.pop("login", None)
    if not exp: raise HTTPException(400, "Challenge no encontrado")
    raw = body.get("credential", {}).get("rawId") or body.get("rawId")
    if not raw: raise HTTPException(400, "Credencial invalida")
    row = await pool.fetchrow("SELECT * FROM webauthn_credentials WHERE credential_id = $1", raw)
    if not row: raise HTTPException(404, "Credencial desconocida")
    try:
        v = verify_authentication_response(credential=body["credential"],
            expected_challenge=exp, expected_origin=WEBAUTHN_ORIGIN,
            expected_rp_id=WEBAUTHN_RP_ID,
            credential_public_key=base64url_to_bytes(row["public_key"]),
            credential_current_sign_count=row["sign_count"],
            require_user_verification=False)
    except Exception as e:
        raise HTTPException(400, f"Auth: {e}")
    await pool.execute(
        "UPDATE webauthn_credentials SET sign_count = $1 WHERE credential_id = $2",
        v.new_sign_count, row["credential_id"])
    t = secrets.token_urlsafe(32)
    SESSIONS[t] = {"username": row["username"], "level": 2, "created_at": time.time()}
    response.set_cookie("session", t, max_age=SESSION_TTL, httponly=True,
                        secure=USE_HTTPS, samesite="strict", path="/")
    return {"ok": True, "kind": row["kind"], "username": row["username"]}

@app.get("/api/webauthn/has")
async def wac_has():
    row = await pool.fetchrow(
        "SELECT kind FROM webauthn_credentials ORDER BY created_at DESC LIMIT 1")
    cnt = await pool.fetchval("SELECT COUNT(*) FROM webauthn_credentials") or 0
    if not row: return {"has": False, "kind": None, "count": 0}
    return {"has": True, "kind": row["kind"], "count": cnt}

@app.post("/api/webauthn/delete-all")
async def wac_del_all(request: Request):
    u = _sess_user(request)
    if not u: raise HTTPException(401, "Sesion invalida")
    await pool.execute("DELETE FROM webauthn_credentials WHERE username = $1", u)
    return {"ok": True}

@app.get("/api/webauthn/list")
async def wac_list(request: Request):
    u = _sess_user(request)
    if not u: raise HTTPException(401, "Sesion invalida")
    rows = await pool.fetch(
        "SELECT credential_id, kind, created_at FROM webauthn_credentials WHERE username = $1", u)
    return {"credentials": [dict(r) for r in rows]}

# ─── Push ────────────────────────────────────────────────────────────
@app.get("/api/push/vapid")
async def push_vapid(): return {"public_key": VAPID_PUBLIC}

@app.post("/api/push/subscribe")
async def push_sub(request: Request):
    u = _sess_user(request)
    if not u: raise HTTPException(401, "Sesion invalida")
    body = await request.json()
    sub = body.get("subscription")
    if not sub: raise HTTPException(400, "Suscripcion invalida")
    sid = hashlib.sha1(json.dumps(sub, sort_keys=True).encode()).hexdigest()
    await pool.execute(
        "INSERT INTO push_subscriptions (id,username,subscription,created_at) "
        "VALUES ($1,$2,$3,$4) ON CONFLICT (id) DO UPDATE SET subscription = $3",
        sid, u, json.dumps(sub), int(time.time()))
    return {"ok": True}

async def send_webpush(username: str):
    if not HAS_WEBPUSH or not VAPID_PRIVATE or not VAPID_PUBLIC:
        return
    rows = await pool.fetch(
        "SELECT id, subscription FROM push_subscriptions WHERE username = $1", username)
    if not rows: return
    dead = []
    for r in rows:
        try:
            webpush(
                subscription_info=json.loads(r["subscription"]),
                data=json.dumps({"title": "Aviso",
                                 "body": "Tienes una notificacion nueva"}),
                vapid_private_key=VAPID_PRIVATE,
                vapid_claims={"sub": VAPID_SUBJECT},
            )
        except WebPushException as e:
            log.warning(f"push fail {r['id']}: {e}")
            dead.append(r["id"])
        except Exception as e:
            log.warning(f"push err: {e}")
    for sid in dead:
        await pool.execute("DELETE FROM push_subscriptions WHERE id = $1", sid)

# ─── WebSocket ───────────────────────────────────────────────────────
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    t = ws.cookies.get("session")
    s = SESSIONS.get(t) if t else None
    if not s or s.get("level", 0) < 2:
        await ws.close(code=4401); return
    u = s["username"]; p = get_peer(u)
    await ws.accept()
    CONNECTIONS.setdefault(u, set()).add(ws)
    log.info(f"{u} connected")
    if p: await send_to(p, {"type": "presence_online", "user": u})
    await ws.send_json({"type": "presence",
                        "peer_online": is_online(p) if p else False})

    try:
        rows = await pool.fetch("""
            SELECT m.id, m.sender, m.receiver, m.text, m.created_at,
                   m.status, m.reply_to,
                   r.sender AS r_sender, r.text AS r_text
            FROM messages m
            LEFT JOIN messages r ON r.id = m.reply_to
            WHERE m.sender = $1 OR m.receiver = $1
            ORDER BY m.created_at ASC
        """, u)
        log.info(f"snapshot {u}: {len(rows)}")
        for r in rows:
            robj = None
            if r["reply_to"]:
                robj = {"id": r["reply_to"], "from": r["r_sender"] or "",
                        "text": r["r_text"] or "(sin texto)"}
            await ws.send_json({"type": "message", "message_id": r["id"],
                "text": r["text"], "created_at": r["created_at"],
                "status": r["status"], "from": r["sender"], "reply_to": robj})
    except Exception as e:
        log.error(f"snapshot: {e}")

    try:
        while True:
            data = await ws.receive_json()
            await handle_ws(u, data)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.error(f"ws({u}): {e}")
    finally:
        c = CONNECTIONS.get(u)
        if c: c.discard(ws)
        log.info(f"{u} disconnected")
        if p and not is_online(u):
            await send_to(p, {"type": "presence_offline", "user": u})

async def handle_ws(u: str, data: dict):
    t = data.get("type"); p = get_peer(u)

    if t == "clear_all":
        try:
            await pool.execute(
                "DELETE FROM messages WHERE sender = $1 OR receiver = $1", u)
        except Exception as e:
            log.error(f"clear_all: {e}")
        await send_to(u, {"type": "messages_cleared"})
        if p: await send_to(p, {"type": "messages_cleared"})
        return

    if t == "message":
        text = (data.get("text") or "").strip()
        if not text or len(text) > MAX_TEXT_LEN or not p: return
        reply_to = (data.get("reply_to") or "").strip() or None
        cmid = (data.get("message_id") or "").strip()
        mid = cmid if re.match(r"^[a-f0-9]{32}$", cmid or "") else uuid.uuid4().hex
        ct = int(time.time())
        try:
            await pool.execute(
                "INSERT INTO messages (id,sender,receiver,text,created_at,status,reply_to) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING",
                mid, u, p, text, ct, "sent", reply_to)
        except Exception as e:
            log.error(f"insert: {e}"); return

        await send_to(u, {"type": "message", "message_id": mid, "text": text,
            "created_at": ct, "status": "sent", "from": u, "reply_to": reply_to})

        if is_online(p):
            await send_to(p, {"type": "message", "message_id": mid, "text": text,
                "created_at": ct, "status": "delivered", "from": u, "reply_to": reply_to})
            try:
                await pool.execute(
                    "UPDATE messages SET status='delivered' WHERE id=$1 AND status='sent'", mid)
            except Exception: pass
            await send_to(u, {"type": "message_delivered", "message_id": mid})
        else:
            asyncio.create_task(send_webpush(p))
        return

    if t == "message_seen":
        mid = data.get("message_id")
        if not mid: return
        try:
            await pool.execute(
                "UPDATE messages SET status='read' "
                "WHERE id=$1 AND receiver=$2 AND status!='read'", mid, u)
        except Exception as e:
            log.error(f"seen: {e}"); return
        row = await pool.fetchrow("SELECT sender, receiver FROM messages WHERE id=$1", mid)
        if row:
            payload = {"type": "message_seen", "message_id": mid}
            await send_to(row["sender"], payload)
            await send_to(row["receiver"], payload)
        return

    if t == "typing_start" and p: await send_to(p, {"type": "typing_start"})
    if t == "typing_stop"  and p: await send_to(p, {"type": "typing_stop"})

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    cert = os.getenv("SSL_CERT"); key = os.getenv("SSL_KEY")
    kw = {"host": host, "port": port, "log_level": "info",
          "loop": "asyncio", "http": "h11", "ws": "wsproto"}
    if cert and key and Path(cert).exists() and Path(key).exists():
        kw["ssl_certfile"] = cert; kw["ssl_keyfile"] = key
        log.info(f"HTTPS {host}:{port}")
    else:
        log.info(f"HTTP {host}:{port}")
    uvicorn.run(app, **kw)
