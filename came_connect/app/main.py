# -*- coding: utf-8 -*-
import base64
import hashlib
import json
import os
import secrets
import time
from typing import Tuple, Dict, Any

import httpx
from fastapi import FastAPI, HTTPException


# ---- Config ----
CLIENT_ID = os.getenv("CAME_CONNECT_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CAME_CONNECT_CLIENT_SECRET", "")
USERNAME = os.getenv("CAME_CONNECT_USERNAME", "")
PASSWORD = os.getenv("CAME_CONNECT_PASSWORD", "")

# Base API pour les commandes/statuts
API_BASE_CANDIDATES = [
    "https://app.cameconnect.net/api/evo/v1",
]

# Endpoint OAuth (auth.cameconnect.net) – pris du custom component
AUTH_BASE = "https://app.cameconnect.net/api/oauth/token"

# URI de redirection tel que documenté dans sdeagh
REDIRECT_URI = "https://app.cameconnect.net/role"

TOKEN_PATH = "/data/token.json"
HTTP_TIMEOUT = 30.0




app = FastAPI(title="Came Connect Proxy", version="0.2.1")


# ---- Utility ----
def _pkce_pair() -> Tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(32)).replace("-", "").replace("_", "")
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge

    return bool(tok and tok.get("access_token"))


def _safe_json(resp: httpx.Response):
    try:
        return resp.json()
    except Exception:
        return None


def fetch_token() -> Dict[str, Any]:
    """
    Obtenir un access_token via grant_type=password sur auth.cameconnect.net,
    en copiant le flow utilisé par sdeagh/yashijoe.
    """
    if not all([CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD]):
        raise HTTPException(
            status_code=500,
            detail="Configuration manquante (CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)."
        )

    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Authorization": _basic_auth(CLIENT_ID, CLIENT_SECRET),
    }

    # Body aligné sur le custom component : grant_type=password
    body = {
        "grant_type": "password",
        "username": USERNAME,
        "password": PASSWORD,
        "scope": "openid profile offline_access",
    }

    try:
        with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True) as s:
            r = s.post(AUTH_BASE, data=body, headers=headers)

        if r.status_code != 200:
            # On renvoie le contenu pour debug, comme dans le custom component
            raise HTTPException(
                status_code=502,
                detail={
                    "message": "OAuth failed (token)",
                    "status": r.status_code,
                    "body": r.text[:1000],
                },
            )

        tok = r.json()
        # Optionnel, mais pratique pour debug
        tok["_auth_base"] = AUTH_BASE
        save_token(tok)
        return tok

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail={
                "message": "OAuth exception",
                "error": str(e),
                "type": type(e).__name__,
            },
        )

def ensure_token() -> Tuple[str, str]:
    tok = load_token()
        else:
            r = s.get(url, headers=headers)

        if r.status_code == 401:
            fetch_token()
            access, _ = ensure_token()
            headers["Authorization"] = f"Bearer {access}"
            if method.upper() == "POST":
                r = s.post(url, headers=headers, json=payload)
            else:
                r = s.get(url, headers=headers)

    return r

        return None
