"""
Mensajeria - chat privado 2 usuarios.
- Mensajes persistidos en Neon (PostgreSQL). Sin TTL.
- Usuarios desde env vars.
- Boton 'clear_all' borra todo.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, Optional, Set

import asyncpg
import uvicorn
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

from fastapi import (
    FastAPI, Form, HTTPException, Request, Response, WebSocket, WebSocketDisconnect,
)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

SESSION_TTL  = 60 * 60 * 8
MAX_TEXT_LEN = 4000
USE_HTTPS    = os.getenv("USE_HTTPS", "0") == "1"
WEBAUTHN_RP_ID   = os.getenv("WEBAUTHN_RP_ID",   "localhost")
WEBAUTHN_RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "Mensajeria")
WEBAUTHN_ORIGIN  = os.getenv("WEBAUTHN_ORIGIN",  "http://localhost:8000")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("mensajeria")

# ─── Password hashing ─────────────────────────────────────────────────
SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN = 2**14, 8, 1, 32

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode(), salt=salt,
                         n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(key).decode()

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_b64, key_b64 = stored.split("$", 1)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(key_b64)
        key = hashlib.scrypt(password.encode(), salt=salt,
                             n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)
        return hmac.compare_digest(key, expected)
    except Exception:
        return False

# ─── Usuarios desde env vars ──────────────────────────────────────────
def load_users() -> Dict[str, dict]:
    users = {}
    for letter in ("A", "B"):
        name = os.getenv(f"USER_{letter}_NAME", "").strip()
        pw   = os.getenv(f"USER_{letter}_PASSWORD", "")
        pin  = os.getenv(f"USER_{letter}_PIN", "")
        if name and pw:
            users[name] = {"hash": hash_password(pw), "pin": pin}
    return users

USERS: Dict[str, dict] = load_users()
log.info(f"usuarios cargados: {list(USERS.keys())}")

def get_peer(username: str) -> Optional[str]:
    for u in USERS.keys():
        if u != username:
            return u
    return None

# ─── Estado RAM ───────────────────────────────────────────────────────
SESSIONS:    Dict[str, dict]        = {}
CONNECTIONS: Dict[str, Set[WebSocket]] = {}
pool: Optional[asyncpg.Pool]        = None

def is_online(user: str) -> bool:
    return bool(CONNECTIONS.get(user))

async def send_to(user: str, payload: dict) -> None:
    conns = CONNECTIONS.get(user)
    if not conns:
        return
    dead = []
    for ws in list(conns):
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        conns.discard(ws)

# ─── Neon ─────────────────────────────────────────────────────────────
async def init_db():
    raw = os.getenv("DATABASE_URL", "")
    if not raw:
        raise RuntimeError("Falta DATABASE_URL")
    clean = raw.replace("&channel_binding=require", "").replace("channel_binding=require", "")
    for attempt in range(1, 6):
        try:
            p = await asyncpg.create_pool(
                clean, min_size=1, max_size=3,
                timeout=60, command_timeout=60,
                statement_cache_size=0,
            )
            async with p.acquire() as con:
                await con.execute("""
                    CREATE TABLE IF NOT EXISTS messages (
                        id TEXT PRIMARY KEY,
                        sender TEXT NOT NULL,
                        receiver TEXT NOT NULL,
                        text TEXT NOT NULL,
                        created_at BIGINT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'sent',
                        reply_to TEXT
                    );
                """)
                await con.execute("CREATE INDEX IF NOT EXISTS idx_msg_sender   ON messages(sender)")
                await con.execute("CREATE INDEX IF NOT EXISTS idx_msg_receiver ON messages(receiver)")
                await con.execute("""
                    CREATE TABLE IF NOT EXISTS webauthn_credentials (
                        credential_id TEXT PRIMARY KEY,
                        username      TEXT NOT NULL,
                        public_key    TEXT NOT NULL,
                        sign_count    BIGINT NOT NULL DEFAULT 0,
                        kind          TEXT NOT NULL DEFAULT 'chat',
                        created_at    BIGINT NOT NULL
                    );
                """)
                await con.execute("CREATE INDEX IF NOT EXISTS idx_wac_user ON webauthn_credentials(username)")
                # Migrar tabla vieja si existe
                await con.execute("""
                    DO $$
                    BEGIN
                        IF EXISTS (SELECT FROM information_schema.tables
                                   WHERE table_schema='public' AND table_name='messages_unread') THEN
                            INSERT INTO messages (id, sender, receiver, text, created_at, status, reply_to)
                            SELECT id, sender, receiver, text, created_at, status, reply_to
                            FROM messages_unread
                            ON CONFLICT (id) DO NOTHING;
                            DROP TABLE messages_unread;
                        END IF;
                    END $$;
                """)
            log.info("Neon conectado, tabla 'messages' lista")
            return p
        except Exception as e:
            log.warning(f"init_db intento {attempt}/5 falló: {type(e).__name__}: {e}")
            await asyncio.sleep(2 * attempt)
    raise RuntimeError("No se pudo conectar a Neon tras 5 intentos")

@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    pool = await init_db()
    yield
    if pool:
        await pool.close()

app = FastAPI(title="Mensajeria", lifespan=lifespan)
if Path("static").exists():
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.middleware("http")
async def no_cache_html(request, call_next):
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.endswith(".html"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

# ─── Rutas ────────────────────────────────────────────────────────────
@app.get("/")
async def index():
    return FileResponse("templates/index.html")

@app.get("/ia")
async def page_ia():
    return FileResponse("templates/ia.html")

@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)

@app.get("/api/status")
async def api_status():
    return {"ok": True, "users": list(USERS.keys()), "max_users": len(USERS)}

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get("session")
    sess  = SESSIONS.get(token) if token else None
    if not sess:
        return {"authenticated": False}
    user = sess["username"]
    peer = get_peer(user)
    return {
        "authenticated": True,
        "username": user,
        "level": sess["level"],
        "peer": peer,
        "peer_online": is_online(peer) if peer else False,
    }

@app.post("/api/login")
async def api_login(request: Request, response: Response,
                    username: str = Form(...), password: str = Form(...)):
    username = username.strip()
    stored = USERS.get(username)
    if not (stored and verify_password(password, stored["hash"])):
        await asyncio.sleep(0.4)
        raise HTTPException(401, "Credenciales incorrectas")
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {"username": username, "level": 1, "created_at": time.time()}
    response.set_cookie("session", token, max_age=SESSION_TTL,
                        httponly=True, secure=USE_HTTPS, samesite="strict", path="/")
    return {"ok": True, "step": "pin"}

@app.post("/api/pin")
async def api_pin(request: Request, pin: str = Form(...)):
    token = request.cookies.get("session")
    sess  = SESSIONS.get(token) if token else None
    if not sess:
        raise HTTPException(401, "Sesion invalida")
    expected = USERS.get(sess["username"], {}).get("pin", "")
    if not secrets.compare_digest(expected, pin.strip()):
        await asyncio.sleep(0.4)
        raise HTTPException(401, "PIN incorrecto")
    sess["level"] = 2
    return {"ok": True}

@app.post("/api/logout")
async def api_logout(request: Request, response: Response):
    token = request.cookies.get("session")
    if token:
        SESSIONS.pop(token, None)
    response.delete_cookie("session", path="/")
    return {"ok": True}

@app.post("/api/register")
async def api_register():
    raise HTTPException(403, "Registro deshabilitado. Configura los usuarios por variables de entorno.")


# ─── WebAuthn ─────────────────────────────────────────────────────────
CHALLENGES: Dict[str, bytes] = {}   # challenge temporal en RAM, se borra al usarlo

def _session_user(request: Request) -> Optional[str]:
    token = request.cookies.get("session")
    sess  = SESSIONS.get(token) if token else None
    return sess["username"] if sess else None

@app.post("/api/webauthn/register/begin")
async def wac_register_begin(request: Request):
    user = _session_user(request)
    if not user:
        raise HTTPException(401, "Sesion invalida")
    existing = await pool.fetch(
        "SELECT credential_id FROM webauthn_credentials WHERE username = $1", user
    )
    exclude = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"]))
               for r in existing]
    options = generate_registration_options(
        rp_id=WEBAUTHN_RP_ID,
        rp_name=WEBAUTHN_RP_NAME,
        user_id=user.encode("utf-8"),
        user_name=user,
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    CHALLENGES["reg:" + user] = options.challenge
    return Response(content=options_to_json(options), media_type="application/json")

@app.post("/api/webauthn/register/finish")
async def wac_register_finish(request: Request):
    user = _session_user(request)
    if not user:
        raise HTTPException(401, "Sesion invalida")
    body = await request.json()
    expected = CHALLENGES.pop("reg:" + user, None)
    if not expected:
        raise HTTPException(400, "Challenge no encontrado")
    try:
        verification = verify_registration_response(
            credential=body["credential"],
            expected_challenge=expected,
            expected_origin=WEBAUTHN_ORIGIN,
            expected_rp_id=WEBAUTHN_RP_ID,
            require_user_verification=False,
        )
    except Exception as e:
        raise HTTPException(400, f"Registro fallido: {e}")
    cred_id = bytes_to_base64url(verification.credential_id)
    pub_key = bytes_to_base64url(verification.credential_public_key)
    kind = (body.get("kind") or "chat").lower()
    if kind not in ("chat", "ia"):
        kind = "chat"
    await pool.execute(
        "INSERT INTO webauthn_credentials (credential_id, username, public_key, sign_count, kind, created_at) "
        "VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (credential_id) DO UPDATE SET kind = $5",
        cred_id, user, pub_key, verification.sign_count, kind, int(time.time()),
    )
    return {"ok": True, "kind": kind}

@app.post("/api/webauthn/login/begin")
async def wac_login_begin():
    rows = await pool.fetch(
        "SELECT credential_id FROM webauthn_credentials"
    )
    if not rows:
        raise HTTPException(404, "No hay credenciales registradas")
    allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"]))
             for r in rows]
    options = generate_authentication_options(
        rp_id=WEBAUTHN_RP_ID,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    CHALLENGES["login"] = options.challenge
    return Response(content=options_to_json(options), media_type="application/json")

@app.post("/api/webauthn/login/finish")
async def wac_login_finish(request: Request, response: Response):
    body = await request.json()
    expected = CHALLENGES.pop("login", None)
    if not expected:
        raise HTTPException(400, "Challenge no encontrado")
    raw_id = body.get("credential", {}).get("rawId") or body.get("rawId")
    if not raw_id:
        raise HTTPException(400, "Credencial invalida")
    row = await pool.fetchrow(
        "SELECT * FROM webauthn_credentials WHERE credential_id = $1", raw_id
    )
    if not row:
        raise HTTPException(404, "Credencial desconocida")
    try:
        verification = verify_authentication_response(
            credential=body["credential"],
            expected_challenge=expected,
            expected_origin=WEBAUTHN_ORIGIN,
            expected_rp_id=WEBAUTHN_RP_ID,
            credential_public_key=base64url_to_bytes(row["public_key"]),
            credential_current_sign_count=row["sign_count"],
            require_user_verification=False,
        )
    except Exception as e:
        raise HTTPException(400, f"Autenticacion fallida: {e}")
    await pool.execute(
        "UPDATE webauthn_credentials SET sign_count = $1 WHERE credential_id = $2",
        verification.new_sign_count, row["credential_id"],
    )
    # Crear sesion completa (level 2) directamente
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {"username": row["username"], "level": 2, "created_at": time.time()}
    response.set_cookie("session", token, max_age=SESSION_TTL,
                        httponly=True, secure=USE_HTTPS, samesite="strict", path="/")
    return {"ok": True, "kind": row["kind"], "username": row["username"]}

@app.get("/api/webauthn/list")
async def wac_list(request: Request):
    user = _session_user(request)
    if not user:
        raise HTTPException(401, "Sesion invalida")
    rows = await pool.fetch(
        "SELECT credential_id, kind, created_at FROM webauthn_credentials WHERE username = $1",
        user,
    )
    return {"credentials": [{"id": r["credential_id"], "kind": r["kind"],
                             "created_at": r["created_at"]} for r in rows]}

@app.post("/api/webauthn/delete")
async def wac_delete(request: Request):
    user = _session_user(request)
    if not user:
        raise HTTPException(401, "Sesion invalida")
    body = await request.json()
    kind = (body.get("kind") or "").lower()
    if kind not in ("chat", "ia"):
        raise HTTPException(400, "kind invalido")
    await pool.execute(
        "DELETE FROM webauthn_credentials WHERE username = $1 AND kind = $2",
        user, kind,
    )
    return {"ok": True}

# ─── WebSocket ────────────────────────────────────────────────────────
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    token = ws.cookies.get("session")
    sess  = SESSIONS.get(token) if token else None
    if not sess or sess.get("level", 0) < 2:
        await ws.close(code=4401)
        return
    user = sess["username"]
    peer = get_peer(user)
    await ws.accept()
    CONNECTIONS.setdefault(user, set()).add(ws)
    log.info(f"{user} connected")

    if peer:
        await send_to(peer, {"type": "presence_online", "user": user})
    await ws.send_json({"type": "presence",
                        "peer_online": is_online(peer) if peer else False})

    # Snapshot desde Neon: TODOS los mensajes donde participa este user
    try:
        rows = await pool.fetch(
            "SELECT id, sender, receiver, text, created_at, status, reply_to "
            "FROM messages WHERE sender = $1 OR receiver = $1 ORDER BY created_at ASC",
            user,
        )
        log.info(f"snapshot {user}: {len(rows)} mensajes")
        for row in rows:
            await ws.send_json({
                "type":       "message",
                "message_id": row["id"],
                "text":       row["text"],
                "created_at": row["created_at"],
                "status":     row["status"],
                "from":       row["sender"],
                "reply_to":   row["reply_to"],
            })
    except Exception as e:
        log.error(f"snapshot error: {type(e).__name__}: {e}")

    try:
        while True:
            data = await ws.receive_json()
            await handle_ws(user, data)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.error(f"ws({user}): {type(e).__name__}: {e}")
    finally:
        conns = CONNECTIONS.get(user)
        if conns:
            conns.discard(ws)
        log.info(f"{user} disconnected")
        if peer and not is_online(user):
            await send_to(peer, {"type": "presence_offline", "user": user})

async def handle_ws(user: str, data: dict) -> None:
    t    = data.get("type")
    peer = get_peer(user)

    # ── Borrar TODO ──
    if t == "clear_all":
        try:
            await pool.execute(
                "DELETE FROM messages WHERE sender = $1 OR receiver = $1",
                user,
            )
        except Exception as e:
            log.error(f"clear_all: {e}")
        payload = {"type": "messages_cleared"}
        await send_to(user, payload)
        if peer:
            await send_to(peer, payload)
        log.info(f"clear_all por {user}")
        return

    # ── Enviar mensaje ──
    if t == "message":
        text = (data.get("text") or "").strip()
        if not text or len(text) > MAX_TEXT_LEN or not peer:
            return
        reply_to   = (data.get("reply_to") or "").strip() or None
        client_mid = (data.get("message_id") or "").strip()
        mid = client_mid if re.match(r"^[a-f0-9]{32}$", client_mid or "") else uuid.uuid4().hex
        created_at = int(time.time())

        try:
            await pool.execute(
                "INSERT INTO messages (id, sender, receiver, text, created_at, status, reply_to) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO NOTHING",
                mid, user, peer, text, created_at, "sent", reply_to,
            )
        except Exception as e:
            log.error(f"insert: {e}")
            return

        # Eco al emisor
        await send_to(user, {
            "type": "message", "message_id": mid, "text": text,
            "created_at": created_at, "status": "sent",
            "from": user, "reply_to": reply_to,
        })

        # Al peer si está online
        if is_online(peer):
            await send_to(peer, {
                "type": "message", "message_id": mid, "text": text,
                "created_at": created_at, "status": "delivered",
                "from": user, "reply_to": reply_to,
            })
            try:
                await pool.execute(
                    "UPDATE messages SET status = 'delivered' "
                    "WHERE id = $1 AND status = 'sent'",
                    mid,
                )
            except Exception:
                pass
            await send_to(user, {"type": "message_delivered", "message_id": mid})
        return

    # ── Visto ──
    if t == "message_seen":
        mid = data.get("message_id")
        if not mid:
            return
        try:
            await pool.execute(
                "UPDATE messages SET status = 'read' "
                "WHERE id = $1 AND receiver = $2 AND status != 'read'",
                mid, user,
            )
        except Exception as e:
            log.error(f"message_seen: {e}")
            return
        row = await pool.fetchrow(
            "SELECT sender, receiver FROM messages WHERE id = $1", mid
        )
        if row:
            payload = {"type": "message_seen", "message_id": mid}
            await send_to(row["sender"], payload)
            await send_to(row["receiver"], payload)
        return

    # ── Typing ──
    if t == "typing_start" and peer:
        await send_to(peer, {"type": "typing_start"})
        return
    if t == "typing_stop" and peer:
        await send_to(peer, {"type": "typing_stop"})
        return

# ─── Entrypoint ───────────────────────────────────────────────────────
if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    cert = os.getenv("SSL_CERT")
    key  = os.getenv("SSL_KEY")
    kwargs = {
        "host": host, "port": port, "log_level": "info",
        "loop": "asyncio", "http": "h11", "ws": "wsproto",
    }
    if cert and key and Path(cert).exists() and Path(key).exists():
        kwargs["ssl_certfile"] = cert
        kwargs["ssl_keyfile"]  = key
        log.info(f"HTTPS/WSS en https://{host}:{port}")
    else:
        log.info(f"HTTP en http://{host}:{port}")
    uvicorn.run(app, **kwargs)
