# -*- coding: utf-8 -*-
import base64
import hashlib
import json
import os
import secrets
import time
from typing import Tuple, Dict, Any

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from __future__ import annotations
# ---- Config ----
CLIENT_ID = os.getenv("CAME_CONNECT_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CAME_CONNECT_CLIENT_SECRET", "")
USERNAME = os.getenv("CAME_CONNECT_USERNAME", "")
PASSWORD = os.getenv("CAME_CONNECT_PASSWORD", "")

API_BASE_CANDIDATES = [
    "https://app.cameconnect.net/api/evo/v1",
]

APP_BASE = "https://app.cameconnect.net"
AUTH_AUTHORIZE_URL = f"{APP_BASE}/api/oauth/auth-code"
AUTH_TOKEN_URL = f"{APP_BASE}/api/oauth/token"
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://192.168.1.104:9002").rstrip("/")
REDIRECT_URI = f"{PUBLIC_BASE_URL}/auth/callback"
TOKEN_PATH = "/data/token.json"
HTTP_TIMEOUT = 30.0
PKCE_MAX_AGE_SECONDS = 600

app = FastAPI(title="Came Connect Proxy", version="0.3.0")

PKCE_STORE: Dict[str, Dict[str, Any]] = {}


# ---- Utility ----
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pkce_pair() -> Tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(48))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _basic_auth(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def load_token() -> Dict[str, Any] | None:
    try:
        with open(TOKEN_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return None


def save_token(tok: Dict[str, Any]) -> None:
    try:
        with open(TOKEN_PATH, "w") as f:
            json.dump(tok, f)
    except Exception:
        pass


def token_valid(tok: Dict[str, Any] | None) -> bool:
    return bool(tok and tok.get("access_token"))


def cleanup_pkce_store(max_age_seconds: int = PKCE_MAX_AGE_SECONDS) -> None:
    now = time.time()
    expired = [k for k, v in PKCE_STORE.items() if now - v.get("created_at", 0) > max_age_seconds]
    for k in expired:
        PKCE_STORE.pop(k, None)


def fetch_token() -> Dict[str, Any]:
    tok = load_token()
    if tok and tok.get("access_token"):
        return tok
    raise HTTPException(
        status_code=401,
        detail={
            "message": "No token stored yet",
            "action": f"Open {PUBLIC_BASE_URL}/auth/start in a browser to authenticate with CAME"
        },
    )


def ensure_token() -> Tuple[str, str]:
    tok = load_token()
    if not token_valid(tok):
        tok = fetch_token()
    return tok["access_token"], tok.get("_base") or API_BASE_CANDIDATES[0]


def _request_with_refresh(method: str, url: str, payload=None):
    access, _ = ensure_token()
    headers = {"Authorization": f"Bearer {access}", "Accept": "application/json"}

    with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True) as s:
        if method.upper() == "POST":
            r = s.post(url, headers=headers, json=payload)
        else:
            r = s.get(url, headers=headers)

    return r


def _try_command_requests(access: str, base: str, device_id: int, command_id: int) -> Dict[str, Any]:
    candidates = [
        ("POST", f"{base}/automations/{device_id}/commands/{command_id}", None),
        ("POST", f"{base}/devices/{device_id}/commands/{command_id}", None),
        ("GET", f"{base}/devices/{device_id}/command/{command_id}", None),
    ]
    last = None
    for method, url, payload in candidates:
        try:
            r = _request_with_refresh(method, url, payload)
            if r.status_code in (200, 202, 204):
                return {"ok": True, "method": method, "url": url, "status": r.status_code}
            last = {"ok": False, "method": method, "url": url, "status": r.status_code, "body": r.text}
        except Exception as e:
            last = {"ok": False, "method": method, "url": url, "error": str(e), "type": type(e).__name__}
    return last or {"ok": False, "error": "unknown"}


def _fetch_states(device_id: int) -> list[dict]:
    access, base = ensure_token()
    candidates = [
        f"{base}/automations/{device_id}/info",
        f"{base}/devices/{device_id}/info",
        f"{base}/automations/{device_id}/status",
        f"{base}/devices/{device_id}/status",
        f"{base}/devicestatus?devices=%5B{device_id}%5D",
    ]
    last = None
    for url in candidates:
        r = _request_with_refresh("GET", url)
        if r.status_code != 200:
            last = {"status": r.status_code, "url": url, "body": r.text}
            continue
        try:
            j = r.json()
        except Exception:
            raise HTTPException(status_code=502, detail={"message": "invalid JSON", "url": url, "raw": r.text})

        data = j.get("Data")
        if isinstance(data, list) and data:
            if isinstance(data[0], dict) and data[0].get("States"):
                return data[0]["States"]
        if isinstance(data, dict) and data.get("States"):
            return data["States"]

        last = {"status": r.status_code, "url": url, "body": j}

    raise HTTPException(status_code=502, detail={"message": "no States found in any endpoint", "last": last})


def _decode_maneuvers_from_states(states: list[dict]) -> int | None:
    if not isinstance(states, list):
        return None
    state18 = next((s for s in states if isinstance(s, dict) and s.get("CommandId") == 18), None)
    if not state18:
        return None
    d = state18.get("Data") or []
    if not (isinstance(d, list) and len(d) >= 8):
        return None
    try:
        part1 = int(d[2]) * 256 + int(d[3])
        part2 = int(d[6]) * 256 + int(d[7])
        return part1 + part2
    except Exception:
        return None


# ---- PKCE OAuth flow ----
@app.get("/auth/start")
def auth_start():
    if not CLIENT_ID or not CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Missing client credentials")

    cleanup_pkce_store()

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    code_verifier, code_challenge = _pkce_pair()

    PKCE_STORE[state] = {
        "code_verifier": code_verifier,
        "nonce": nonce,
        "created_at": time.time(),
    }

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    url = httpx.URL(AUTH_AUTHORIZE_URL, params=params)
    return RedirectResponse(str(url), status_code=302)


@app.get("/auth/callback")
def auth_callback(
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
):
    if error:
        raise HTTPException(status_code=502, detail={"message": "OAuth callback error", "error": error})

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state")

    ctx = PKCE_STORE.pop(state, None)
    if not ctx:
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    code_verifier = ctx["code_verifier"]

    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Authorization": _basic_auth(CLIENT_ID, CLIENT_SECRET),
    }

    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
        "client_id": CLIENT_ID,
    }

    try:
        with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True) as s:
            r = s.post(AUTH_TOKEN_URL, data=token_data, headers=headers)

        if r.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail={
                    "message": "OAuth token exchange failed",
                    "status": r.status_code,
                    "body": r.text[:1000],
                },
            )

        tok = r.json()
        tok["_base"] = API_BASE_CANDIDATES[0]
        tok["_redirect_uri"] = REDIRECT_URI
        save_token(tok)

        return HTMLResponse("""
        <html>
          <body style="font-family: sans-serif; padding: 2rem;">
            <h1>Authentification CAME réussie</h1>
            <p>Le token a été enregistré dans l'add-on. Tu peux revenir dans Home Assistant.</p>
          </body>
        </html>
        """)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail={"message": "OAuth exception", "error": str(e), "type": type(e).__name__},
        )


# ---- API ----
@app.get("/health")
def health():
    return {"ok": True, "redirect_uri": REDIRECT_URI}


@app.get("/devices/{device_id}/commands")
def list_commands(device_id: int):
    access, base = ensure_token()
    urls = [
        f"{base}/automations/{device_id}/commands",
        f"{base}/devices/{device_id}/commands",
    ]
    last = None
    for u in urls:
        r = _request_with_refresh("GET", u)
        if r.status_code == 200:
            try:
                return {"ok": True, "base": base, "url": u, "data": r.json()}
            except Exception:
                return {"ok": True, "base": base, "url": u, "raw": r.text}
        last = {"status": r.status_code, "url": u, "body": r.text}
    raise HTTPException(status_code=502, detail={"message": "no commands endpoint worked", "last": last})


@app.get("/devices/{device_id}/status")
def device_status(device_id: int):
    try:
        access, base = ensure_token()
        url = f"{base}/automations/{device_id}/status"
        r = _request_with_refresh("GET", url)
        if r.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail={"message": "status fetch failed", "status": r.status_code, "body": r.text, "url": url}
            )

        data = r.json()
        ok = bool(data.get("Success"))
        payload = data.get("Data") or {}
        online = bool(payload.get("Online", True))
        states = payload.get("States") or []

        by_cmd = {e.get("CommandId"): e for e in states if isinstance(e, dict)}

        code_map = {
            16: "open",
            17: "closed",
            19: "stopped",
            32: "opening",
            33: "closing",
        }

        code = None
        pos_entry = by_cmd.get(1)
        if pos_entry and isinstance(pos_entry.get("Data"), list) and len(pos_entry["Data"]) >= 1:
            try:
                code = int(pos_entry["Data"][0])
            except Exception:
                code = None

        moving_flag = False
        mv_entry = by_cmd.get(3)
        if mv_entry and isinstance(mv_entry.get("Data"), list) and len(mv_entry["Data"]) >= 1:
            try:
                moving_flag = int(mv_entry["Data"][0]) == 1
            except Exception:
                moving_flag = False

        state = code_map.get(code, "unknown")
        if state == "unknown" and moving_flag:
            state = "moving"

        if state in ("opening", "closing"):
            direction = state
        elif state == "stopped":
            direction = "stopped"
        else:
            direction = "unknown"

        if state == "open":
            position = 100
        elif state == "closed":
            position = 0
        else:
            position = None

        timestamps = []
        for e in (pos_entry, mv_entry):
            if e and e.get("UpdatedAt"):
                timestamps.append(e["UpdatedAt"])
        updated_at = max(timestamps) if timestamps else payload.get("ConfiguredLastUpdate")

        maneuvers = None
        try:
            maneuvers = _decode_maneuvers_from_states(states)
            if maneuvers is None:
                alt_states = _fetch_states(device_id)
                maneuvers = _decode_maneuvers_from_states(alt_states)
        except Exception as sub_e:
            maneuvers = f"decode_error: {sub_e}"

        return {
            "ok": ok,
            "base": base,
            "url": url,
            "state": state,
            "position": position,
            "moving": state in ("opening", "closing") or moving_flag,
            "direction": direction,
            "online": online,
            "raw_code": code,
            "updated_at": updated_at,
            "maneuvers": maneuvers,
            "raw": data,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": type(e).__name__})


@app.get("/devices/{device_id}/maneuvers")
def maneuvers(device_id: int):
    states = _fetch_states(device_id)
    count = _decode_maneuvers_from_states(states)
    if count is None:
        raise HTTPException(status_code=502, detail={"message": "maneuvers not found in States", "states": states})
    return {"ok": True, "device_id": device_id, "maneuvers": count, "source": "States/CommandId=18"}


@app.get("/devices/{device_id}/command/{command_id}")
def exec_command(device_id: int, command_id: int):
    access, base = ensure_token()
    res = _try_command_requests(access, base, device_id, command_id)
    if res.get("ok"):
        return {"success": True, "used": {"method": res["method"], "url": res["url"], "status": res["status"]}}
    raise HTTPException(status_code=502, detail=res)


@app.get("/debug/token")
def debug_token():
    try:
        access, base = ensure_token()
        return {
            "ok": True,
            "base": base,
            "access_token_present": bool(access),
            "auth_start_url": f"{PUBLIC_BASE_URL}/auth/start",
            "redirect_uri": REDIRECT_URI,
        }
    except HTTPException as e:
        return {
            "ok": False,
            "status_code": e.status_code,
            "detail": e.detail,
            "auth_start_url": f"{PUBLIC_BASE_URL}/auth/start",
            "redirect_uri": REDIRECT_URI,
        }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "type": type(e).__name__,
            "auth_start_url": f"{PUBLIC_BASE_URL}/auth/start",
            "redirect_uri": REDIRECT_URI,
        }


@app.get("/debug/token_detail")
def token_detail():
    try:
        access, base = ensure_token()

        def _jwt_payload(jwt: str):
            try:
                parts = jwt.split(".")
                pad = "=" * (-len(parts[1]) % 4)
                return json.loads(base64.urlsafe_b64decode((parts[1] + pad).encode()).decode("utf-8"))
            except Exception:
                return None

        payload = _jwt_payload(access) if access else None
        exp = payload.get("exp") if payload else None
        now = int(time.time())

        return {
            "ok": bool(access),
            "base": base,
            "has_payload": bool(payload),
            "exp": exp,
            "expires_in_s": (exp - now) if exp else None,
            "redirect_uri": REDIRECT_URI,
        }
    except HTTPException as e:
        return {
            "ok": False,
            "status_code": e.status_code,
            "detail": e.detail,
            "redirect_uri": REDIRECT_URI,
        }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "type": type(e).__name__,
            "redirect_uri": REDIRECT_URI,
        }
