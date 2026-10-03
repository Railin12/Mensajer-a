"""
Mensajeria — chat privado con Neon.
- Mensajes NO LEIDOS en Neon (tabla messages_unread)
- Al leer, se mueve a disco local y se borra de Neon, inicia TTL de 25min
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import re
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, Optional, Set

import asyncpg
import uvicorn
from fastapi import (
    FastAPI, Form, HTTPException, Request, Response, WebSocket, WebSocketDisconnect,
)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
load_dotenv()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
MESSAGE_TTL = 1500
CLEANUP_INTERVAL = 5
SESSION_TTL = 60 * 60 * 8
MAX_TEXT_LEN = 4000
MAX_USERS = int(os.getenv("MAX_USERS", "2"))
MAX_LOGIN_TRIES = 5
LOGIN_WINDOW = 300
USE_HTTPS = os.getenv("USE_HTTPS", "0") == "1"
DATABASE_URL = os.getenv("DATABASE_URL")

DATA_ROOT = Path("data")
DATA_DIR = DATA_ROOT / "messages"
TMP_DIR = DATA_ROOT / "tmp"
USERS_FILE = DATA_ROOT / "users.json"

for d in (DATA_ROOT, DATA_DIR, TMP_DIR):
    d.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("mensajeria")

# pool global para Neon
pool: Optional[asyncpg.Pool] = None

# ---------------------------------------------------------------------------
# DB Neon
# ---------------------------------------------------------------------------
async def init_db():
    """Conecta a Neon con reintentos y backoff. Fuerza loop asyncio fuera de uvloop."""
    raw = os.getenv("DATABASE_URL", "")
    if not raw:
        raise RuntimeError("Falta DATABASE_URL")
    clean_url = raw.replace("&channel_binding=require", "").replace("channel_binding=require", "")

    last_err = None
    for attempt in range(1, 6):
        try:
            pool = await asyncpg.create_pool(
                clean_url,
                min_size=1,
                max_size=3,
                timeout=60,
                command_timeout=60,
                statement_cache_size=0,
            )
            async with pool.acquire() as con:
                await con.execute("""
                    CREATE TABLE IF NOT EXISTS messages_unread (
                        id TEXT PRIMARY KEY,
                        sender TEXT NOT NULL,
                        receiver TEXT NOT NULL,
                        text TEXT NOT NULL,
                        created_at BIGINT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'sent',
                        reply_to TEXT
                    );
                """)
                await con.execute("""
                    CREATE INDEX IF NOT EXISTS idx_receiver ON messages_unread(receiver);
                """)
                await con.execute("""
                    ALTER TABLE messages_unread ADD COLUMN IF NOT EXISTS reply_to TEXT;
                """)
            log.info("Neon conectado y tabla messages_unread lista")
            return pool
        except Exception as e:
            last_err = e
            log.warning(f"init_db intento {attempt}/5 falló: {type(e).__name__}: {e}")
            await asyncio.sleep(2 * attempt)
    raise RuntimeError(f"No se pudo conectar a Neon tras 5 intentos: {last_err}")


async def write_message_db(mid, meta, text):
    await pool.execute("""
        INSERT INTO messages_unread (id, sender, receiver, text, created_at, status)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (id) DO NOTHING
    """, mid, meta["sender"], meta["receiver"], text, meta["created_at"], meta["status"])

# ---------------------------------------------------------------------------
# Password hashing con scrypt
# ---------------------------------------------------------------------------
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(key).decode()

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_b64, key_b64 = stored.split("$", 1)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(key_b64)
        key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)
        return hmac.compare_digest(key, expected)
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Usuarios
# ---------------------------------------------------------------------------
ENV_USERS = {
    os.getenv("USER_A_NAME", "").strip(): {"password": os.getenv("USER_A_PASSWORD", ""), "pin": os.getenv("USER_A_PIN", "")},
    os.getenv("USER_B_NAME", "").strip(): {"password": os.getenv("USER_B_PASSWORD", ""), "pin": os.getenv("USER_B_PIN", "")},
}

def _atomic_write(path: Path, data) -> None:
    tmp = TMP_DIR / f"{path.name}.{uuid.uuid4().hex}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, path)

def load_users() -> Dict[str, dict]:
    users: Dict[str, dict] = {}
    if USERS_FILE.exists():
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                users = json.load(f)
        except Exception as e:
            log.error(f"users.json corrupto: {e}")
            users = {}
    changed = False
    for u, d in ENV_USERS.items():
        if not u or not d.get("password"):
            continue
        if u not in users:
            users[u] = {"hash": hash_password(d["password"]), "pin": d.get("pin") or "0000"}
            changed = True
    if changed or not USERS_FILE.exists():
        _atomic_write(USERS_FILE, users)
    return users

USERS: Dict[str, dict] = load_users()
log.info(f"usuarios cargados: {list(USERS.keys())}")

def get_peer(username: str) -> Optional[str]:
    for u in USERS.keys():
        if u!= username:
            return u
    return None

# ---------------------------------------------------------------------------
# Estado en RAM
# ---------------------------------------------------------------------------
SESSIONS: Dict[str, dict] = {}
LOGIN_ATTEMPTS: Dict[str, list] = {}
MESSAGES: Dict[str, dict] = {}
CONNECTIONS: Dict[str, Set[WebSocket]] = {}

def is_online(user: str) -> bool:
    return bool(CONNECTIONS.get(user))

# ---------------------------------------------------------------------------
# Persistencia local (solo para mensajes LEIDOS)
# ---------------------------------------------------------------------------
def write_message(mid: str, meta: dict, text: str) -> str:
    path = DATA_DIR / f"{mid}.json"
    _atomic_write(path, {"meta": meta, "text": text})
    return str(path)

def persist_meta(mid: str) -> None:
    meta = MESSAGES.get(mid)
    if not meta:
        return
    path = Path(meta["file_path"])
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return
    data["meta"]["status"] = meta["status"]
    data["meta"]["expires_at"] = meta["expires_at"]
    _atomic_write(path, data)

def read_text(mid: str) -> Optional[str]:
    meta = MESSAGES.get(mid)
    if not meta:
        return None
    try:
        with open(meta["file_path"], "r", encoding="utf-8") as f:
            return json.load(f).get("text")
    except Exception as e:
        log.error(f"read_text({mid}): {e}")
        return None

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

async def delete_message(mid: str) -> None:
    meta = MESSAGES.pop(mid, None)
    if not meta:
        return
    try:
        Path(meta["file_path"]).unlink(missing_ok=True)
    except Exception as e:
        log.error(f"unlink({mid}): {e}")
    payload = {"type": "message_deleted", "message_id": mid}
    await send_to(meta["sender"], payload)
    await send_to(meta["receiver"], payload)
    log.info(f"expired {mid}")

# ---------------------------------------------------------------------------
# Arranque y limpieza
# ---------------------------------------------------------------------------
async def recover_from_disk() -> None:
    now = time.time()
    kept = dropped = 0
    for f in DATA_DIR.glob("*.json"):
        try:
            with open(f, "r", encoding="utf-8") as fp:
                data = json.load(fp)
        except Exception as e:
            log.warning(f"corrupto {f.name}: {e}; borrando")
            f.unlink(missing_ok=True)
            continue
        meta = data.get("meta") or {}
        mid = meta.get("id")
        if not mid:
            f.unlink(missing_ok=True)
            continue
        if meta.get("status") == "read" and meta.get("expires_at") and now >= meta["expires_at"]:
            f.unlink(missing_ok=True)
            dropped += 1
            continue
        MESSAGES[mid] = {
            "id": mid, "sender": meta.get("sender"), "receiver": meta.get("receiver"),
            "status": meta.get("status", "sent"), "created_at": meta.get("created_at", int(now)),
            "expires_at": meta.get("expires_at"), "file_path": str(f),
        }
        kept += 1
    log.info(f"recover: kept={kept} dropped={dropped}")

async def cleanup_loop() -> None:
    """Deshabilitado: los mensajes no expiran. Solo se borran con 'clear_all'."""
    while True:
        await asyncio.sleep(3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await recover_from_disk()
    task = asyncio.create_task(cleanup_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    if pool:
        await pool.close()

app = FastAPI(title="Mensajeria", lifespan=lifespan)

@app.middleware("http")
async def no_cache_html(request, call_next):
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.endswith(".html"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

if Path("static").exists():
    app.mount("/static", StaticFiles(directory="static"), name="static")

# ---------------------------------------------------------------------------
# Rutas basicas
# ---------------------------------------------------------------------------
@app.get("/")
async def index():
    return FileResponse("templates/index.html")

@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)

@app.get("/api/status")
async def api_status():
    return {"can_register": len(USERS) < MAX_USERS, "slots": max(0, MAX_USERS - len(USERS)), "max_users": MAX_USERS}

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get("session")
    sess = SESSIONS.get(token) if token else None
    if not sess:
        return {"authenticated": False}
    user = sess["username"]
    peer = get_peer(user)
    return {"authenticated": True, "username": user, "level": sess["level"], "peer": peer, "peer_online": is_online(peer) if peer else False}

# ---------------------------------------------------------------------------
# Registro / Login / PIN / Logout
# ---------------------------------------------------------------------------
def _check_rate(ip: str) -> None:
    now = time.time()
    attempts = LOGIN_ATTEMPTS.setdefault(ip, [])
    attempts[:] = [t for t in attempts if now - t < LOGIN_WINDOW]
    if len(attempts) >= MAX_LOGIN_TRIES:
        raise HTTPException(429, "Demasiados intentos, espera unos minutos.")
    attempts.append(now)

@app.post("/api/register")
async def api_register(request: Request, username: str = Form(...), password: str = Form(...), pin: str = Form(...)):
    ip = request.client.host if request.client else "?"
    _check_rate(ip)
    if len(USERS) >= MAX_USERS:
        raise HTTPException(403, "Capacidad maxima alcanzada")
    username = username.strip()
    if not username or len(username) > 32:
        raise HTTPException(400, "Usuario invalido (1-32)")
    if username in USERS:
        raise HTTPException(409, "Ese usuario ya existe")
    if len(password) < 6:
        raise HTTPException(400, "Contrasena muy corta")
    if not pin.isdigit() or not (4 <= len(pin) <= 8):
        raise HTTPException(400, "PIN 4-8 digitos")
    USERS[username] = {"hash": hash_password(password), "pin": pin}
    _atomic_write(USERS_FILE, USERS)
    log.info(f"nuevo usuario: {username}")
    return {"ok": True, "username": username}

@app.post("/api/login")
async def api_login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host if request.client else "?"
    _check_rate(ip)
    username = username.strip()
    stored = USERS.get(username)
    ok = bool(stored) and verify_password(password, stored["hash"])
    if not ok:
        await asyncio.sleep(0.4)
        raise HTTPException(401, "Credenciales incorrectas")
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {"username": username, "level": 1, "created_at": time.time()}
    response.set_cookie("session", token, max_age=SESSION_TTL, httponly=True, secure=USE_HTTPS, samesite="strict", path="/")
    return {"ok": True, "step": "pin"}

@app.post("/api/pin")
async def api_pin(request: Request, pin: str = Form(...)):
    token = request.cookies.get("session")
    sess = SESSIONS.get(token) if token else None
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

# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    token = ws.cookies.get("session")
    sess = SESSIONS.get(token) if token else None
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
    await ws.send_json({"type": "presence", "peer_online": is_online(peer) if peer else False})

    now = time.time()
    # 1. Mensajes leidos en disco (RAM)
    for mid, meta in list(MESSAGES.items()):
        if user not in (meta["sender"], meta["receiver"]):
            continue
        if meta["status"] == "read" and meta["expires_at"] and now >= meta["expires_at"]:
            continue
        text = read_text(mid)
        if text is None:
            continue
        try:
            await ws.send_json({"type": "message", "message_id": mid, "text": text, "created_at": meta["created_at"], "status": meta["status"], "from": meta["sender"], "expires_at": meta["expires_at"]})
        except Exception:
            break

    # 2. Mensajes NO LEIDOS desde Neon (snapshot)
    try:
        rows = await pool.fetch("SELECT * FROM messages_unread WHERE sender = $1 OR receiver = $1 ORDER BY created_at ASC", user)
        for row in rows:
            await ws.send_json({
                "type": "message",
                "message_id": row["id"],
                "text": row["text"],
                "created_at": row["created_at"],
                "status": row["status"],
                "from": row["sender"],
                "expires_at": None,
            })
    except Exception as e:
        log.error(f"snapshot Neon error: {e}")

    try:
        while True:
            data = await ws.receive_json()
            await handle_ws(user, data)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.error(f"ws({user}): {e}")
    finally:
        conns = CONNECTIONS.get(user)
        if conns:
            conns.discard(ws)
        log.info(f"{user} disconnected")
        if peer and not is_online(user):
            await send_to(peer, {"type": "presence_offline", "user": user})

async def handle_ws(user: str, data: dict) -> None:
    t = data.get("type")
    peer = get_peer(user)

    if t == "message":
        text = (data.get("text") or "").strip()
        if not text or len(text) > MAX_TEXT_LEN or not peer:
            return
        reply_to = (data.get("reply_to") or "").strip() or None
        client_mid = (data.get("message_id") or "").strip()
        if client_mid and re.match(r"^[a-f0-9]{32}$", client_mid):
            # verificar que no exista en Neon ni RAM
            exists_disk = client_mid in MESSAGES
            exists_db = await pool.fetchval("SELECT 1 FROM messages_unread WHERE id = $1", client_mid)
            mid = client_mid if not exists_disk and not exists_db else uuid.uuid4().hex
        else:
            mid = uuid.uuid4().hex
        created_at = int(time.time())
        meta = {"id": mid, "sender": user, "receiver": peer, "status": "sent", "created_at": created_at, "expires_at": None}

        # Guardar en Neon
        await write_message_db(mid, meta, text)

        await send_to(user, {"type": "message", "message_id": mid, "text": text, "created_at": created_at, "status": "sent", "from": user, "expires_at": None})

        if is_online(peer):
            await send_to(peer, {"type": "message", "message_id": mid, "text": text, "created_at": created_at, "status": "delivered", "from": user, "expires_at": None})
            # actualizar status a delivered en Neon
            await pool.execute("UPDATE messages_unread SET status = 'delivered' WHERE id = $1", mid)
            await send_to(user, {"type": "message_delivered", "message_id": mid})
        return

    if t == "message_seen":
        mid = data.get("message_id")
        if not mid:
            return
        # Solo cambia el estado a 'read' en Neon. NO se borra ni se expira.
        try:
            await pool.execute(
                "UPDATE messages_unread SET status = 'read' WHERE id = $1 AND receiver = $2",
                mid, user
            )
        except Exception as e:
            log.error(f"message_seen update: {e}")
            return
        # Sacar del índice RAM (ya no es necesario, todo vive en Neon)
        MESSAGES.pop(mid, None)
        # Notificar a ambos
        row = await pool.fetchrow(
            "SELECT sender, receiver FROM messages_unread WHERE id = $1", mid
        )
        if row:
            payload = {"type": "message_seen", "message_id": mid}
            await send_to(row["sender"], payload)
            await send_to(row["receiver"], payload)
        return

    if t == "typing_start" and peer:
        await send_to(peer, {"type": "typing_start"})
        return
    if t == "typing_stop" and peer:
        await send_to(peer, {"type": "typing_stop"})
        return

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    cert = os.getenv("SSL_CERT")
    key  = os.getenv("SSL_KEY")
    kwargs = {
        "host": host,
        "port": port,
        "log_level": "info",
        "loop": "asyncio",        # ← fuerza el loop estándar, no uvloop
        "http": "h11",            # ← fuerza http parser h11 (no httptools)
        "ws": "wsproto",          # ← fuerza parser ws puro Python
    }
    if cert and key and Path(cert).exists() and Path(key).exists():
        kwargs["ssl_certfile"] = cert
        kwargs["ssl_keyfile"]  = key
        log.info(f"HTTPS/WSS en https://{host}:{port}")
    else:
        log.info(f"HTTP en http://{host}:{port}")
    uvicorn.run(app, **kwargs)
