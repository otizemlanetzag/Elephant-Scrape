from __future__ import annotations

import json
import os
import secrets
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

BLOB_TOKEN = os.environ.get("BLOB_READ_WRITE_TOKEN") or os.environ.get("VERCEL_BLOB_READ_WRITE_TOKEN")
BLOB_BASE = "https://blob.vercel-storage.com"

def _blob_path(path: Path) -> str:
    # Keep the per-user path, but never expose the machine's absolute path.
    parts = list(path.parts)
    marker = "connections"
    if marker in parts:
        uid = parts[parts.index(marker) - 1] if parts.index(marker) else "unknown"
    else:
        uid = path.parent.name or "unknown"
    return f"elephant-scrape/{uid}/connections/connections.json"

def _blob_call(path: Path, method: str = "GET", data: bytes | None = None):
    if not BLOB_TOKEN: return None
    req = urllib.request.Request(
        BLOB_BASE + "/" + _blob_path(path), method=method, data=data,
        headers={"Authorization":"Bearer "+BLOB_TOKEN,"x-api-version":"7","x-content-type":"application/json", "x-add-random-suffix":"0", "x-allow-overwrite":"1"})
    try:
        with urllib.request.urlopen(req, timeout=30) as response: return response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404: return None
        raise

OAUTH = {
    "google": {
        "name": "Google Drive",
        "client_id": "GOOGLE_CLIENT_ID",
        "client_secret": "GOOGLE_CLIENT_SECRET",
        "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
        "token": "https://oauth2.googleapis.com/token",
        "scope": "https://www.googleapis.com/auth/drive.file",
    },
    "dropbox": {
        "name": "Dropbox",
        "client_id": "DROPBOX_CLIENT_ID",
        "client_secret": "DROPBOX_CLIENT_SECRET",
        "authorize": "https://www.dropbox.com/oauth2/authorize",
        "token": "https://api.dropboxapi.com/oauth2/token",
        "scope": "files.content.write files.content.read account_info.read",
    },
    "onedrive": {
        "name": "OneDrive",
        "client_id": "ONEDRIVE_CLIENT_ID",
        "client_secret": "ONEDRIVE_CLIENT_SECRET",
        "authorize": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "scope": "offline_access Files.ReadWrite",
    },
}

def cipher():
    key = os.environ.get("ELEPHANT_SERVER_KEY")
    return Fernet(key.encode()) if key else None

def load(path: Path) -> list[dict[str, Any]]:
    try:
        raw = _blob_call(path) if BLOB_TOKEN else None
        if BLOB_TOKEN and raw is None:
            return []
        if raw is not None:
            data = json.loads(raw.decode("utf-8"))
        else:
            if not path.exists(): return []
            data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return []
        f = cipher()
        if f:
            for item in data:
                if item.get("token"):
                    item["token"] = f.decrypt(item["token"].encode()).decode()
        return data
    except Exception:
        return []

def save(path: Path, items: list[dict[str, Any]]) -> None:
    f = cipher()
    if not f:
        raise RuntimeError("ELEPHANT_SERVER_KEY is required for token storage.")
    stored = json.loads(json.dumps(items))
    for item in stored:
        if item.get("token"):
            item["token"] = f.encrypt(item["token"].encode()).decode()
    payload = json.dumps(stored, ensure_ascii=False, indent=2).encode("utf-8")
    if BLOB_TOKEN:
        _blob_call(path, "PUT", payload)
        return
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(payload)
    os.replace(tmp, path)

def start_oauth(provider: str, redirect_uri: str):
    cfg = OAUTH.get(provider)
    if not cfg:
        raise ValueError("Unknown provider")
    client_id = os.environ.get(cfg["client_id"])
    if not client_id:
        raise RuntimeError(cfg["name"] + " OAuth is not configured.")
    state = secrets.token_urlsafe(32)
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state,
        "scope": cfg["scope"],
    }
    if provider == "google":
        params["access_type"] = "offline"
        params["prompt"] = "consent"
    if provider == "dropbox":
        params["token_access_type"] = "offline"
    return state, cfg["authorize"] + "?" + urllib.parse.urlencode(params)

def finish_oauth(provider: str, code: str, redirect_uri: str) -> dict:
    cfg = OAUTH[provider]
    body = {
        "client_id": os.environ[cfg["client_id"]],
        "client_secret": os.environ.get(cfg["client_secret"], ""),
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    req = urllib.request.Request(
        cfg["token"],
        data=urllib.parse.urlencode(body).encode(),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))
