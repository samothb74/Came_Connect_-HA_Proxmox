import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

app = FastAPI(title="CAME Connect API bridge", version="2.0.1")

CLIENT_ID = os.getenv("CAME_CONNECT_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CAME_CONNECT_CLIENT_SECRET", "")
DEVICE_ID = os.getenv("CAME_CONNECT_DEVICE_ID", "")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")

AUTH_URL = "https://app.cameconnect.net/api/oauth/mfa/auth-code"
TOKEN_URL = "https://app.cameconnect.net/api/oauth/token"
REDIRECT_URI = "https://cameconnect.net/role"

API_BASE = "https://app.cameconnect.net/api"
HTTP_TIMEOUT = 30.0

DATA_DIR = Path("/data")
TOKEN_FILE = DATA_DIR / "token.json"
FLOW_FILE = DATA_DIR / "oauth_flow.json"


def _ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pkce_pair() -> Tuple[str, str]:
    code_verifier = _b64url(secrets.token_bytes(64))
    code_challenge = _b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())
    return code_verifier, code_challenge


def _basic_auth(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def load_json_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_json_file(path: Path, payload: Dict[str, Any]) -> None:
    _ensure_data_dir()
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_token() -> Dict[str, Any]:
    return load_json_file(TOKEN_FILE)


def save_token(tok: Dict[str, Any]) -> None:
    save_json_file(TOKEN_FILE, tok)


def load_flow() -> Dict[str, Any]:
    return load_json_file(FLOW_FILE)


def save_flow(flow: Dict[str, Any]) -> None:
    save_json_file(FLOW_FILE, flow)


def token_valid(tok: Dict[str, Any]) -> bool:
    access_token = tok.get("access_token")
    expires_at = tok.get("expires_at", 0)
    if not access_token:
        return False
    return time.time() < (expires_at - 60)


def _normalize_token_payload(tok: Dict[str, Any]) -> Dict[str, Any]:
    expires_in = int(tok.get("expires_in", 3600))
    tok["expires_at"] = int(time.time()) + expires_in
    return tok


def build_auth_url() -> Dict[str, str]:
    if not CLIENT_ID:
        raise HTTPException(status_code=500, detail="Missing CAME_CONNECT_CLIENT_ID")

    code_verifier, code_challenge = _pkce_pair()
    state = secrets.token_urlsafe(48)
    nonce = secrets.token_urlsafe(48)

    flow = {
        "state": state,
        "nonce": nonce,
        "code_verifier": code_verifier,
        "redirect_uri": REDIRECT_URI,
        "created_at": int(time.time()),
        "auth_url": AUTH_URL,
        "token_url": TOKEN_URL,
    }
    save_flow(flow)

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    url = f"{AUTH_URL}?{urlencode(params)}"

    return {
        "auth_url": url,
        "state": state,
        "redirect_uri": REDIRECT_URI,
        "instructions": (
            "Open auth_url in a browser, log in to CAME Connect, "
            "then capture the final redirected URL and extract the 'code' parameter. "
            "Call /auth/exchange?code=...&state=... to complete authentication."
        ),
    }


def exchange_code_for_token(code: str, state: str) -> Dict[str, Any]:
    if not CLIENT_ID:
        raise HTTPException(status_code=500, detail="Missing CAME_CONNECT_CLIENT_ID")

    flow = load_flow()
    if not flow:
        raise HTTPException(status_code=400, detail="No OAuth flow in progress")

    expected_state = flow.get("state")
    code_verifier = flow.get("code_verifier")
    redirect_uri = flow.get("redirect_uri", REDIRECT_URI)

    if not expected_state or not code_verifier:
        raise HTTPException(status_code=400, detail="Stored OAuth flow is incomplete")

    if state != expected_state:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Accept": "application/json",
    }

    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }

    if CLIENT_SECRET:
        headers["Authorization"] = _basic_auth(CLIENT_ID, CLIENT_SECRET)

    with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True) as s:
        r = s.post(TOKEN_URL, data=data, headers=headers)

    if r.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail={
                "message": "OAuth token exchange failed",
                "status": r.status_code,
                "body": r.text[:1500],
            },
        )

    tok = _normalize_token_payload(r.json())
    tok["_token_url"] = TOKEN_URL
    tok["_redirect_uri"] = redirect_uri
    tok["_auth_mode"] = "authorization_code_pkce"
    save_token(tok)

    return {
        "ok": True,
        "auth_mode": "authorization_code_pkce",
        "expires_at": tok.get("expires_at"),
        "has_refresh_token": bool(tok.get("refresh_token")),
    }


def refresh_token_if_possible(tok: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not CLIENT_ID:
        return None

    refresh_token = tok.get("refresh_token")
    if not refresh_token:
        return None

    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Accept": "application/json",
    }

    data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": refresh_token,
    }

    if CLIENT_SECRET:
        headers["Authorization"] = _basic_auth(CLIENT_ID, CLIENT_SECRET)

    with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True) as s:
        r = s.post(TOKEN_URL, data=data, headers=headers)

    if r.status_code != 200:
        return None

    new_tok = _normalize_token_payload(r.json())
    new_tok["_token_url"] = TOKEN_URL
    new_tok["_redirect_uri"] = tok.get("_redirect_uri", REDIRECT_URI)
    new_tok["_auth_mode"] = "authorization_code_pkce"
    save_token(new_tok)
    return new_tok


def ensure_token() -> Dict[str, Any]:
    tok = load_token()

    if token_valid(tok):
        return tok

    refreshed = refresh_token_if_possible(tok)
    if refreshed and token_valid(refreshed):
        return refreshed

    raise HTTPException(
        status_code=401,
        detail={
            "message": "No valid token available",
            "action": "Start a new login with /auth/start, then complete /auth/exchange",
        },
    )


def _auth_headers(access_token: str) -> Dict[str, str]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    if DEVICE_ID:
        headers["x-device-id"] = DEVICE_ID
    return headers


def _request_with_refresh(
    method: str,
    url: str,
    payload: Optional[Dict[str, Any]] = None,
) -> httpx.Response:
    tok = ensure_token()
    headers = _auth_headers(tok["access_token"])

    with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True) as s:
        if method.upper() == "POST":
            r = s.post(url, headers=headers, json=payload)
        else:
            r = s.get(url, headers=headers)

    if r.status_code != 401:
        return r

    refreshed = refresh_token_if_possible(tok)
    if not refreshed:
        return r

    headers = _auth_headers(refreshed["access_token"])
    with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True) as s:
        if method.upper() == "POST":
            return s.post(url, headers=headers, json=payload)
        return s.get(url, headers=headers)


def _fetch_devices() -> Any:
    candidates = [
        f"{API_BASE}/devices",
        f"{API_BASE}/device",
    ]

    last_response = None
    for url in candidates:
        r = _request_with_refresh("GET", url)
        last_response = r
        if r.status_code == 200:
            return r.json()

    raise HTTPException(
        status_code=502,
        detail={
            "message": "Failed to fetch devices",
            "status": last_response.status_code if last_response else None,
            "body": last_response.text[:1200] if last_response else None,
        },
    )


def _fetch_device_states(device_id: str) -> Any:
    candidates = [
        f"{API_BASE}/devices/{device_id}/states",
        f"{API_BASE}/devices/{device_id}/status",
        f"{API_BASE}/device/{device_id}/states",
        f"{API_BASE}/device/{device_id}/status",
    ]

    last_response = None
    for url in candidates:
        r = _request_with_refresh("GET", url)
        last_response = r
        if r.status_code == 200:
            return r.json()

    raise HTTPException(
        status_code=502,
        detail={
            "message": "Failed to fetch device states",
            "status": last_response.status_code if last_response else None,
            "body": last_response.text[:1200] if last_response else None,
        },
    )


def _try_command_requests(device_id: str, command: str) -> Dict[str, Any]:
    payloads = [
        {"command": command},
        {"action": command},
        {"name": command},
        {"maneuver": command},
    ]

    urls = [
        f"{API_BASE}/devices/{device_id}/commands",
        f"{API_BASE}/devices/{device_id}/command",
        f"{API_BASE}/device/{device_id}/commands",
        f"{API_BASE}/device/{device_id}/command",
    ]

    attempts = []
    for url in urls:
        for payload in payloads:
            r = _request_with_refresh("POST", url, payload)
            attempts.append(
                {
                    "url": url,
                    "payload": payload,
                    "status": r.status_code,
                    "body": r.text[:500],
                }
            )
            if r.status_code in (200, 201, 202, 204):
                try:
                    body = r.json()
                except Exception:
                    body = {"raw": r.text[:500]}
                return {"ok": True, "result": body, "attempts": attempts}

    raise HTTPException(
        status_code=502,
        detail={"message": "All command attempts failed", "attempts": attempts},
    )


@app.get("/health")
def health() -> Dict[str, Any]:
    tok = load_token()
    flow = load_flow()
    return {
        "ok": True,
        "client_id_set": bool(CLIENT_ID),
        "client_secret_set": bool(CLIENT_SECRET),
        "device_id_set": bool(DEVICE_ID),
        "public_base_url_set": bool(PUBLIC_BASE_URL),
        "token_present": bool(tok.get("access_token")),
        "token_valid": token_valid(tok),
        "refresh_token_present": bool(tok.get("refresh_token")),
        "oauth_flow_present": bool(flow.get("state")),
        "auth_mode": tok.get("_auth_mode"),
        "redirect_uri": REDIRECT_URI,
    }


@app.get("/auth/start")
def auth_start() -> Dict[str, str]:
    return build_auth_url()


@app.get("/auth/exchange")
def auth_exchange(
    code: str = Query(..., description="Authorization code returned by CAME redirect"),
    state: str = Query(..., description="State returned by CAME redirect"),
) -> Dict[str, Any]:
    return exchange_code_for_token(code, state)


@app.get("/debug/token")
def debug_token() -> Dict[str, Any]:
    tok = load_token()
    return {
        "present": bool(tok),
        "auth_mode": tok.get("_auth_mode"),
        "expires_at": tok.get("expires_at"),
        "token_valid": token_valid(tok),
        "has_access_token": bool(tok.get("access_token")),
        "has_refresh_token": bool(tok.get("refresh_token")),
        "redirect_uri": tok.get("_redirect_uri"),
        "token_url": tok.get("_token_url"),
    }


@app.get("/debug/flow")
def debug_flow() -> Dict[str, Any]:
    flow = load_flow()
    masked = dict(flow) if flow else {}
    if "code_verifier" in masked:
        masked["code_verifier"] = masked["code_verifier"][:8] + "...masked..."
    return masked


@app.get("/devices")
def get_devices() -> JSONResponse:
    return JSONResponse(content=_fetch_devices())


@app.get("/devices/{device_id}/states")
def get_device_states(device_id: str) -> JSONResponse:
    return JSONResponse(content=_fetch_device_states(device_id))


@app.post("/devices/{device_id}/open")
def open_device(device_id: str) -> Dict[str, Any]:
    return _try_command_requests(device_id, "open")


@app.post("/devices/{device_id}/close")
def close_device(device_id: str) -> Dict[str, Any]:
    return _try_command_requests(device_id, "close")


@app.post("/devices/{device_id}/stop")
def stop_device(device_id: str) -> Dict[str, Any]:
    return _try_command_requests(device_id, "stop")
