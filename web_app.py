from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

from flask import Flask, Response, abort, jsonify, redirect, request, send_file, session
from connections import OAUTH, load as load_connections, save as save_connections, start_oauth, finish_oauth
import urllib.parse
import urllib.request

APP_NAME = "Elephant Scrape"
BASE_DIR = Path(os.environ.get("ELEPHANT_DATA_DIR", Path.cwd() / ".elephant_data"))
BASE_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD = int(os.environ.get("ELEPHANT_MAX_UPLOAD", str(512 * 1024 * 1024)))

app = Flask(__name__)
app.secret_key = os.environ.get("ELEPHANT_SESSION_SECRET", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD + 4 * 1024 * 1024
CONNECTIONS = BASE_DIR / "connections" / "connections.json"
CONNECTIONS.parent.mkdir(parents=True, exist_ok=True)
WEBSITES = BASE_DIR / "websites.json"
SITE_CACHE = BASE_DIR / "site_cache"
SITE_CACHE_TTL = 600
SITE_CACHE.mkdir(parents=True, exist_ok=True)


# --- Security hardening -------------------------------------------------
SECURITY_MAX_PATH = 240
SECURITY_MAX_WEBSITE_NAME = 63
SECURITY_ALLOWED_SITE_EXTENSIONS = {
    ".html", ".htm", ".css", ".js", ".json", ".svg",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
    ".txt", ".xml", ".map", ".woff", ".woff2", ".ttf"
}
SECURITY_BLOCKED_SITE_EXTENSIONS = {
    ".py", ".sh", ".bat", ".cmd", ".ps1", ".exe", ".dll",
    ".so", ".dylib", ".php", ".asp", ".aspx", ".jsp"
}

def security_clean_relative_path(value: str) -> str:
    value = str(value or "").replace("\\", "/").strip()
    if len(value) > SECURITY_MAX_PATH:
        abort(400, "Path is too long.")
    parts = [p for p in value.split("/") if p not in ("", ".")]
    if any(p == ".." or "\x00" in p for p in parts):
        abort(403, "Unsafe path.")
    return "/".join(parts)

def security_site_file_allowed(relative: str) -> bool:
    suffix = Path(relative).suffix.lower()
    if suffix in SECURITY_BLOCKED_SITE_EXTENSIONS:
        return False
    return suffix in SECURITY_ALLOWED_SITE_EXTENSIONS or suffix == ""

def security_request_checks():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if request.content_length and request.content_length > MAX_UPLOAD + 4 * 1024 * 1024:
            abort(413, "Request is too large.")
    if len(request.path) > SECURITY_MAX_PATH:
        abort(414, "Request path is too long.")
    user_agent = request.headers.get("User-Agent", "")
    if len(user_agent) > 1024:
        abort(400, "Invalid request headers.")

@app.before_request
def security_before_request():
    security_request_checks()

@app.after_request
def security_hardening_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["X-DNS-Prefetch-Control"] = "off"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
        "form-action 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self';"
    )
    return response
# -------------------------------------------------------------------------

def user_id() -> str:
    uid = session.get("uid")
    if not uid:
        uid = secrets.token_urlsafe(24)
        session["uid"] = uid
    return uid

def user_dir() -> Path:
    path = BASE_DIR / user_id()
    path.mkdir(parents=True, exist_ok=True)
    return path

def safe_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,100}", value or ""):
        abort(400, "Invalid file id")
    return value

def manifest_path() -> Path:
    return user_dir() / "manifest.json"

def load_manifest() -> list[dict[str, Any]]:
    p = manifest_path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []

def save_manifest(items: list[dict[str, Any]]) -> None:
    p = manifest_path()
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, p)

def blob_path(file_id: str) -> Path:
    return user_dir() / (safe_id(file_id) + ".blob")

@app.get("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")

@app.route("/api/index", methods=["GET", "POST", "DELETE"])
def vercel_dispatch():
    """Dispatch Vercel rewrites back to the Flask routes."""
    path = request.args.get("path", "/")
    if path == "/":
        return index()
    if path == "/api/me" and request.method == "GET":
        return api_me()
    match = re.fullmatch(r"/site/google/([A-Za-z0-9_-]+)", path)
    if match and request.method == "GET":
        return render_google_site(match.group(1))
    match = re.fullmatch(r"/site/local/([^/]+)", path)
    if match and request.method == "GET":
        return render_local_site(match.group(1))
    if path == "/api/files" and request.method == "GET":
        return api_files()
    if path == "/api/files" and request.method == "POST":
        return api_upload()
    if path == "/api/connections" and request.method == "GET":
        return api_connections()
    if path == "/api/websites" and request.method == "GET": return api_websites()
    if path == "/api/websites" and request.method == "POST": return api_publish_website()
    match = re.fullmatch(r"/api/websites/([A-Za-z0-9-]+)/sandstorm", path)
    if match and request.method == "POST": return api_add_sandstorm(match.group(1))
    match = re.fullmatch(r"/api/websites/([A-Za-z0-9-]+)", path)
    if match and request.method == "PATCH": return api_update_website(match.group(1))
    if match and request.method == "DELETE": return api_unpublish_website(match.group(1))
    if path == "/api/connections/token" and request.method == "POST":
        return api_token_connection()
    match = re.fullmatch(r"/api/connections/([A-Za-z0-9_-]+)", path)
    if match and request.method == "DELETE":
        return api_disconnect(match.group(1))
    match = re.fullmatch(r"/api/files/([A-Za-z0-9_-]{16,100})", path)
    if match:
        file_id = match.group(1)
        if request.method == "GET":
            return api_download(file_id)
        if request.method == "DELETE":
            return api_delete(file_id)
    match = re.fullmatch(r"/connect/(google|dropbox|onedrive)", path)
    if match and request.method == "GET":
        return api_connect(match.group(1))
    if path == "/oauth/callback" and request.method == "GET": return oauth_callback()
    if request.method == "GET" and not path.startswith("/api/") and not path.startswith("/connect/") and not path.startswith("/oauth/"): return serve_published_site()
    abort(404)

@app.get("/api/connections")
def api_connections():
    return jsonify([{"provider": x["provider"], "name": x["name"], "mode": x["mode"]} for x in load_connections(CONNECTIONS)])

@app.post("/api/connections/token")
def api_token_connection():
    data = request.get_json(silent=True) or {}
    provider = str(data.get("provider", "")).lower()
    token = str(data.get("token", "")).strip()
    if provider not in {"google", "dropbox", "onedrive", "webdav"} or not token:
        abort(400, "Provider and token are required.")
    items = [x for x in load_connections(CONNECTIONS) if x.get("provider") != provider]
    items.append({"provider": provider, "name": data.get("name") or provider.title(), "mode": "token", "token": token})
    save_connections(CONNECTIONS, items)
    return jsonify({"ok": True})

@app.delete("/api/connections/<provider>")
def api_disconnect(provider):
    save_connections(CONNECTIONS, [x for x in load_connections(CONNECTIONS) if x.get("provider") != provider.lower()])
    return jsonify({"ok": True})

@app.get("/connect/<provider>")
def api_connect(provider):
    state, url = start_oauth(provider.lower(), request.url_root.rstrip("/") + "/oauth/callback")
    session["oauth_state"] = state
    session["oauth_provider"] = provider.lower()
    return redirect(url)

@app.get("/oauth/callback")
def oauth_callback():
    provider = session.pop("oauth_provider", None)
    if request.args.get("state") != session.pop("oauth_state", None) or provider not in OAUTH:
        abort(400, "Invalid OAuth connection.")
    code = request.args.get("code")
    if not code:
        abort(400, "The provider did not return an authorization code.")
    tokens = finish_oauth(provider, code, request.url_root.rstrip("/") + "/oauth/callback")
    if not tokens.get("access_token"):
        abort(400, "The provider returned no access token.")
    items = [x for x in load_connections(CONNECTIONS) if x.get("provider") != provider]
    items.append({"provider": provider, "name": OAUTH[provider]["name"], "mode": "oauth", "token": json.dumps(tokens)})
    save_connections(CONNECTIONS, items)
    return redirect("/?connected=" + urllib.parse.quote(OAUTH[provider]["name"]))

def load_websites() -> list[dict[str, Any]]:
    if not WEBSITES.exists(): return []
    try:
        data = json.loads(WEBSITES.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError): return []

def save_websites(items: list[dict[str, Any]]) -> None:
    tmp = WEBSITES.with_suffix(".tmp"); tmp.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8"); os.replace(tmp, WEBSITES)

def valid_site_name(value: str) -> str:
    value = (value or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value): abort(400, "Invalid website name.")
    return value

def valid_site_folder(value: str) -> str:
    value = (value or "").strip().strip("/")
    if not value or ".." in Path(value).parts: abort(400, "Invalid website folder.")
    return value

def api_websites(): return jsonify(load_websites())

def api_publish_website():
    data=request.get_json(silent=True) or {}; folder=valid_site_folder(str(data.get("folder",""))); name=valid_site_name(str(data.get("name",folder.split("/")[-1])))
    domain=str(data.get("domain","")).strip().lower(); base=os.environ.get("ELEPHANT_SITE_BASE_DOMAIN","").strip().lower()
    if not domain:
        if not base: abort(400,"Set ELEPHANT_SITE_BASE_DOMAIN or enter a custom domain.")
        domain=name+"."+base
    if not re.fullmatch(r"[a-z0-9.-]+",domain): abort(400,"Invalid domain.")
    items=[x for x in load_websites() if x.get("domain")!=domain and x.get("name")!=name]
    site={"name":name,"folder":folder,"domain":domain,"provider":str(data.get("provider","local")).lower(),"entrypoint":"index.html","created":int(time.time()),"published":True,"hide_from_search":bool(data.get("hide_from_search",False))}
    items.append(site); save_websites(items); return jsonify(site),201

def api_update_website(name):
    name=valid_site_name(name); data=request.get_json(silent=True) or {}
    items=load_websites(); site=next((x for x in items if x.get("name")==name),None)
    if not site: abort(404)
    if "hide_from_search" in data: site["hide_from_search"]=bool(data["hide_from_search"])
    if "published" in data: site["published"]=bool(data["published"])
    save_websites(items); return jsonify(site)

def api_add_sandstorm(name):
    name=valid_site_name(name)
    items=load_websites(); site=next((x for x in items if x.get("name")==name),None)
    if not site: abort(404)
    site["in_sandstorm"]=True
    site["sandstorm_url"]=site.get("domain")
    save_websites(items)
    return jsonify({"ok":True,"in_sandstorm":True,"url":site.get("domain")})

def api_unpublish_website(name):
    name=valid_site_name(name); items=load_websites(); remaining=[x for x in items if x.get("name")!=name]
    if len(remaining)==len(items): abort(404)
    save_websites(remaining); return jsonify({"ok":True})

def website_for_host(host: str):
    host=(host or "").split(":",1)[0].lower().rstrip("."); return next((x for x in load_websites() if x.get("domain","").lower()==host),None)

def safe_site_path(value: str) -> str:
    value = security_clean_relative_path(urllib.parse.unquote(value or ""))
    if not security_site_file_allowed(value):
        abort(403, "This file type cannot be served as a website resource.")
    parts = [p for p in value.split("/") if p]
    if any(p.startswith(".") for p in parts):
        abort(404)
    return "/".join(parts) or "index.html"

def site_cache_key(site, relative):
    raw = (str(site.get("name","")) + "\0" + relative).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def read_site_cache(site, relative):
    key = site_cache_key(site, relative)
    meta = SITE_CACHE / (key + ".json")
    blob = SITE_CACHE / (key + ".bin")
    try:
        info = json.loads(meta.read_text(encoding="utf-8"))
        if time.time() - float(info["cached_at"]) <= SITE_CACHE_TTL and blob.is_file():
            return blob.read_bytes(), info.get("name", relative)
    except (OSError, ValueError, KeyError, TypeError):
        pass
    try:
        meta.unlink(missing_ok=True); blob.unlink(missing_ok=True)
    except OSError: pass
    return None

def write_site_cache(site, relative, data, name):
    key = site_cache_key(site, relative)
    (SITE_CACHE / (key + ".bin")).write_bytes(data)
    (SITE_CACHE / (key + ".json")).write_text(json.dumps({"cached_at": time.time(), "name": name}), encoding="utf-8")

def cleanup_site_cache():
    cutoff = time.time() - SITE_CACHE_TTL
    for meta in SITE_CACHE.glob("*.json"):
        try:
            info = json.loads(meta.read_text(encoding="utf-8"))
            if float(info.get("cached_at", 0)) < cutoff:
                key = meta.stem; meta.unlink(missing_ok=True); (SITE_CACHE / (key + ".bin")).unlink(missing_ok=True)
        except (OSError, ValueError, TypeError): pass

def serve_published_site():
    site=website_for_host(request.host)
    if not site or not site.get("published", True): abort(404,"Website is not published.")
    if request.path == "/robots.txt":
        body = "User-agent: *\\nDisallow: /\\n" if site.get("hide_from_search", False) else "User-agent: *\\nAllow: /\\n"
        return Response(body, content_type="text/plain; charset=utf-8")
    root=(user_dir()/site["folder"]).resolve(); target=(root/safe_site_path(request.path)).resolve()
    if root not in target.parents and target!=root: abort(404)
    if not target.is_file() and request.path.endswith("/"): target=(root/"index.html").resolve()
    if not target.is_file(): abort(404)
    cleanup_site_cache()
    cached = read_site_cache(site, safe_site_path(request.path))
    if cached:
        data, cached_name = cached
        response = browser_site_response(data, cached_name)
    else:
        data = target.read_bytes()
        write_site_cache(site, safe_site_path(request.path), data, target.name)
        response = browser_site_response(data, target.name)
    if site.get("hide_from_search", False) and target.suffix.lower() in {".html",".htm"}:
        response.headers["X-Robots-Tag"]="noindex, nofollow, noarchive"
    return response

def html_content_type(name: str) -> str | None:
    lower = name.lower()
    if lower.endswith((".html", ".htm")):
        return "text/html; charset=utf-8"
    if lower.endswith(".css"):
        return "text/css; charset=utf-8"
    if lower.endswith(".js"):
        return "text/javascript; charset=utf-8"
    if lower.endswith(".json"):
        return "application/json; charset=utf-8"
    if lower.endswith((".svg",)):
        return "image/svg+xml"
    return None

def browser_site_response(data: bytes, name: str) -> Response:
    content_type = html_content_type(name)
    if not content_type:
        abort(415, "This stored file is not a browser site resource.")
    response = Response(data, content_type=content_type)
    response.headers["Content-Disposition"] = "inline; filename*=UTF-8''" + urllib.parse.quote(name or "index.html")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "sandbox allow-scripts allow-forms allow-popups; "
        "default-src 'self' https: data: blob:; "
        "img-src 'self' https: data: blob:; "
        "style-src 'self' https: 'unsafe-inline'; "
        "script-src 'self' https: 'unsafe-inline' 'unsafe-eval'; "
        "connect-src https:; frame-src https:;"
    )
    return response

def google_connection_token():
    for item in load_connections(CONNECTIONS):
        if item.get("provider") == "google":
            raw = item.get("token")
            if not raw:
                return None
            try:
                return json.loads(raw).get("access_token")
            except (TypeError, ValueError):
                return raw
    return None

@app.get("/site/google/<file_id>")
def render_google_site(file_id):
    token = google_connection_token()
    if not token:
        abort(401, "Connect Google Drive first.")
    meta_req = urllib.request.Request(
        "https://www.googleapis.com/drive/v3/files/" + urllib.parse.quote(file_id, safe="") +
        "?fields=id,name,mimeType,size",
        headers={"Authorization": "Bearer " + token},
    )
    try:
        with urllib.request.urlopen(meta_req, timeout=30) as response:
            meta = json.loads(response.read().decode("utf-8"))
    except Exception:
        abort(404, "Stored file could not be read.")
    name = meta.get("name", "index.html")
    if meta.get("mimeType") == "application/vnd.google-apps.document":
        abort(415, "This is a Google Docs document, not an HTML site file.")
    data_req = urllib.request.Request(
        "https://www.googleapis.com/drive/v3/files/" + urllib.parse.quote(file_id, safe="") + "?alt=media",
        headers={"Authorization": "Bearer " + token},
    )
    try:
        with urllib.request.urlopen(data_req, timeout=60) as response:
            data = response.read()
    except Exception:
        abort(404, "Stored file content could not be downloaded.")
    return browser_site_response(data, name)

@app.get("/site/local/<file_name>")
def render_local_site(file_name):
    # Local storage is another provider: files are stored by Elephant Scrape itself.
    path = user_dir() / file_name
    if not path.is_file() or path.parent != user_dir():
        abort(404)
    return browser_site_response(path.read_bytes(), path.name)

@app.get("/api/me")
def api_me():
    items = load_manifest()
    return jsonify({
        "app": APP_NAME,
        "files": len(items),
        "bytes": sum(int(x.get("size", 0)) for x in items),
        "encrypted_by_client": True,
    })

@app.get("/api/files")
def api_files():
    # Names are encrypted; browser-side search happens after vault unlock.
    return jsonify(load_manifest())

@app.post("/api/files")
def api_upload():
    upload = request.files.get("blob")
    metadata_raw = request.form.get("metadata", "")
    if upload is None or not metadata_raw:
        abort(400, "Encrypted file and metadata are required")
    try:
        metadata = json.loads(metadata_raw)
    except ValueError:
        abort(400, "Invalid metadata")
    if not isinstance(metadata, dict) or not metadata.get("clientEncrypted"):
        abort(400, "Only client-encrypted objects are accepted")

    file_id = secrets.token_urlsafe(24)
    target = blob_path(file_id)
    size = 0
    with target.open("wb") as out:
        while True:
            chunk = upload.stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_UPLOAD:
                out.close()
                target.unlink(missing_ok=True)
                abort(413, "File is too large")
            out.write(chunk)

    record = {"id": file_id, "size": size, "created": int(time.time()), "metadata": metadata}
    items = load_manifest()
    items.append(record)
    save_manifest(items)
    return jsonify(record), 201

@app.get("/api/files/<file_id>")
def api_download(file_id: str):
    path = blob_path(file_id)
    if not path.exists():
        abort(404)
    return send_file(path, mimetype="application/octet-stream", as_attachment=False)

@app.delete("/api/files/<file_id>")
def api_delete(file_id: str):
    safe_id(file_id)
    items = load_manifest()
    remaining = [x for x in items if x.get("id") != file_id]
    if len(remaining) == len(items):
        abort(404)
    blob_path(file_id).unlink(missing_ok=True)
    save_manifest(remaining)
    return jsonify({"ok": True})

INDEX_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Elephant Scrape</title>
<style>
:root{--sand:#F5F2EB;--card:#EFEAE0;--ink:#3E2723;--muted:#6d5b52;--border:#C2A67D;--hover:#D2B48C;--danger:#9b2c2c}
*{box-sizing:border-box}body{margin:0;background:var(--sand);color:var(--ink);font-family:Inter,Segoe UI,Arial,sans-serif}.app{min-height:100vh;display:flex;flex-direction:column}
.top{display:flex;align-items:center;gap:16px;padding:22px 28px;border-bottom:1px solid var(--border)}.logo{font-size:28px;font-weight:800}.tag,.lock{color:var(--muted)}.lock{margin-left:auto;font-size:13px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;padding:14px 28px;background:var(--card);border-bottom:1px solid var(--border)}button{border:1px solid var(--border);background:#fffaf1;color:var(--ink);padding:9px 14px;border-radius:9px;cursor:pointer}button:hover{background:var(--hover)}button.primary{font-weight:700}button.danger{color:var(--danger)}
.main{display:grid;grid-template-columns:230px 1fr;gap:16px;flex:1;padding:18px 28px}.side,.panel{background:var(--card);border:1px solid var(--border);border-radius:14px}.side{padding:16px}.side h3{margin:0 0 14px}.provider{padding:10px;border-radius:8px;background:#fffaf1}.provider small{display:block;color:var(--muted);margin-top:4px}.panel{padding:16px;min-width:0}
.search{display:flex;gap:8px;margin-bottom:14px}.search input{flex:1;border:1px solid var(--border);border-radius:9px;padding:10px 12px;background:#fffdf8;color:var(--ink)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 10px;border-bottom:1px solid #d8cbb9}th{font-size:13px;color:var(--muted)}td.name{font-weight:650}tr.selected{background:#eadfce}.empty{text-align:center;padding:60px 20px;color:var(--muted)}
.status{padding:12px 28px;border-top:1px solid var(--border);color:var(--muted);font-size:13px}.modal{position:fixed;inset:0;background:rgba(62,39,35,.35);display:none;align-items:center;justify-content:center;padding:20px}.modal.open{display:flex}.box{max-width:480px;width:100%;background:var(--sand);border:1px solid var(--border);border-radius:16px;padding:22px}.box h2{margin-top:0}.box input{width:100%;padding:11px;border:1px solid var(--border);border-radius:9px;margin:8px 0 14px;background:white}.warning{background:#fff4df;border-left:4px solid #b07b22;padding:12px;border-radius:7px;margin:10px 0}.actions{display:flex;justify-content:flex-end;gap:8px}.hidden{display:none!important}
@media(max-width:800px){.main{grid-template-columns:1fr;padding:12px}.side{display:none}.top,.toolbar,.status{padding-left:14px;padding-right:14px}.tag{display:none}table th:nth-child(3),table td:nth-child(3){display:none}}
</style></head>
<body>
<div class="app">
<header class="top"><div class="logo">Elephant Scrape</div><div class="tag">privacy-first unified storage</div><div class="lock">🔒 encryption happens in your browser</div></header>
<nav class="toolbar"><button class="primary" id="uploadBtn">Upload</button><button id="refreshBtn">Refresh</button><button id="downloadBtn">Download</button><button class="danger" id="deleteBtn">Delete</button><button id="vaultBtn">Vault</button><button id="connectionsBtn">Connections</button><button id="websiteBtn">Publish Website</button></nav>
<main class="main"><aside class="side"><h3>Storage</h3><div class="provider"><strong>Web storage</strong><small>Encrypted objects on this Elephant Scrape server</small></div><p style="color:var(--muted);font-size:13px;line-height:1.5">Cloud providers can be added behind the same storage adapter without exposing your decrypted files to the server.</p></aside>
<section class="panel"><div class="search"><input id="search" placeholder="Search your decrypted file names…"><button id="searchBtn">Search</button></div><table><thead><tr><th>Name</th><th>Size</th><th>Added</th><th></th></tr></thead><tbody id="files"></tbody></table><div id="empty" class="empty">No files yet. Upload something to start your vault.</div></section></main>
<footer class="status" id="status">Ready.</footer></div>
<input id="fileInput" type="file" multiple class="hidden">
<div class="modal" id="vaultModal"><div class="box"><h2>Vault passphrase</h2><p>Your passphrase stays in this browser tab. It is never sent to Elephant Scrape.</p><input id="passphrase" type="password" autocomplete="new-password" placeholder="Choose or enter your vault passphrase"><div class="warning">If you forget this passphrase, encrypted files cannot be recovered by the server.</div><div class="actions"><button id="vaultCancel">Cancel</button><button class="primary" id="vaultSave">Unlock vault</button></div></div></div>
<div class="modal" id="websiteModal"><div class="box"><h2>Publish a WEBSITE folder</h2><p>Each WEBSITE folder gets its own domain or subdomain.</p><label>Folder</label><input id="websiteFolder" placeholder="my-site"><label>Website name</label><input id="websiteName" placeholder="my-site"><label>Domain (optional)</label><input id="websiteDomain" placeholder="my-site.example.com"><div class="warning">DuckDNS and No-IP can provide DNS/DDNS hostnames. The files remain in Elephant Scrape storage.</div><div class="actions"><button id="websiteCancel">Cancel</button><button class="primary" id="websitePublish">Publish Website</button></div><div id="websiteList" style="margin-top:18px"></div></div></div><div class="modal" id="connectionsModal"><div class="box"><h2>Storage connections</h2><p>Connect normally — no provider IDs are needed. You can also paste a token.</p><div id="connectionList"></div><hr><h3>Token</h3><select id="tokenProvider" style="width:100%;padding:11px"><option value="google">Google Drive</option><option value="dropbox">Dropbox</option><option value="onedrive">OneDrive</option><option value="webdav">WebDAV</option></select><input id="tokenValue" type="password" placeholder="Paste token"><div class="actions"><button id="connectionsClose">Close</button><button class="primary" id="tokenConnect">Connect token</button></div></div></div><script>
const state={key:null,salt:null,files:[]},$=id=>document.getElementById(id),enc=new TextEncoder(),dec=new TextDecoder();
function b64(buf){return btoa(String.fromCharCode(...new Uint8Array(buf)))}function ub64(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
async function derive(pass,salt){const base=await crypto.subtle.importKey('raw',enc.encode(pass),'PBKDF2',false,['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:310000,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}
$('vaultSave').onclick=async()=>{const p=$('passphrase').value;if(p.length<10){alert('Use a passphrase of at least 10 characters.');return}const saved=sessionStorage.getItem('vaultSalt');state.salt=saved?ub64(saved):crypto.getRandomValues(new Uint8Array(16));state.key=await derive(p,state.salt);sessionStorage.setItem('vaultSalt',b64(state.salt));$('passphrase').value='';$('vaultModal').classList.remove('open');setStatus('Vault unlocked.');render()};
$('vaultCancel').onclick=()=> $('vaultModal').classList.remove('open');
async function encryptFile(file){const data=await file.arrayBuffer(),iv=crypto.getRandomValues(new Uint8Array(12)),metadataIv=crypto.getRandomValues(new Uint8Array(12));const meta=enc.encode(JSON.stringify({name:file.name,type:file.type,size:file.size,lastModified:file.lastModified}));const metadataCipher=await crypto.subtle.encrypt({name:'AES-GCM',iv:metadataIv},state.key,meta),cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv},state.key,data);return{blob:new Blob([cipher],{type:'application/octet-stream'}),metadata:{iv:b64(iv),metadataIv:b64(metadataIv),metadataCipher:b64(metadataCipher),salt:b64(state.salt),clientEncrypted:true,version:2}}}
async function decryptMetadata(record){const iv=ub64(record.metadata.metadataIv),plain=await crypto.subtle.decrypt({name:'AES-GCM',iv},state.key,ub64(record.metadata.metadataCipher));return JSON.parse(dec.decode(plain))}
async function decryptFile(record){const r=await fetch('/api/files/'+encodeURIComponent(record.id));if(!r.ok)throw Error('Download failed');const data=await crypto.subtle.decrypt({name:'AES-GCM',iv:ub64(record.metadata.iv),},await r.arrayBuffer());return{data,meta:await decryptMetadata(record)}}
function kind(name){const e=name.toLowerCase().split('.').pop();if(['exe','msi','com','scr','bat','cmd','ps1','vbs','js','jar','dll','sys'].includes(e))return'executable';if(['py','rs','c','h','cpp','cs','java','ts','tsx','jsx','go','rb','php','html','css','sh'].includes(e))return'code';if(['png','jpg','jpeg','gif','webp','bmp','tiff'].includes(e))return'image';if(['txt','md','csv','json','xml','yaml','yml','log'].includes(e))return'text';return'unknown'}
function inspect(file){const k=kind(file.name),target={text:5,image:5,code:10,executable:20,unknown:40}[k],reasons=file.size?[]:['The file is empty.'];return{kind:k,target,reasons,safe:!reasons.length}}
async function upload(){if(!state.key){$('vaultModal').classList.add('open');return}const input=$('fileInput');input.value='';input.click();input.onchange=async()=>{try{for(const file of input.files){const check=inspect(file);if(!check.safe&&!confirm('Security warning: '+check.reasons.join(' ')+'\n\nUpload anyway?'))continue;setStatus('Encrypting '+file.name+'…');const result=await encryptFile(file),fd=new FormData();fd.append('blob',result.blob,file.name+'.es');fd.append('metadata',JSON.stringify(result.metadata));const res=await fetch('/api/files',{method:'POST',body:fd});if(!res.ok)throw Error(await res.text())}await load();setStatus('Upload complete.')}catch(e){setStatus('Upload failed: '+e.message);alert(e.message)}}}
async function load(){const res=await fetch('/api/files');if(!res.ok)throw Error('Could not load files');state.files=await res.json();render()}
async function render(){const q=$('search').value.trim().toLowerCase(),body=$('files');body.innerHTML='';let shown=0;for(const f of state.files){let name='Encrypted file';if(state.key){try{name=(await decryptMetadata(f)).name}catch(e){name='Locked file'}}if(q&&!name.toLowerCase().includes(q))continue;shown++;const tr=document.createElement('tr');tr.innerHTML='<td class="name"></td><td>'+format(f.size)+'</td><td>'+new Date(f.created*1000).toLocaleString()+'</td><td><button data-id="'+f.id+'">Download</button></td>';tr.querySelector('.name').textContent=name;tr.querySelector('button').onclick=()=>download(f);body.appendChild(tr)}$('empty').classList.toggle('hidden',shown>0)}
async function download(record){if(!state.key){$('vaultModal').classList.add('open');return}try{setStatus('Decrypting…');const d=await decryptFile(record),blob=new Blob([d.data],{type:d.meta.type||'application/octet-stream'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=d.meta.name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);setStatus('Downloaded '+d.meta.name)}catch(e){alert('Download failed: '+e.message)}}
async function del(){const tr=document.querySelector('#files tr.selected');if(!tr){alert('Select a file first.');return}const id=tr.querySelector('button').dataset.id;if(!confirm('Delete this encrypted object permanently?'))return;const r=await fetch('/api/files/'+id,{method:'DELETE'});if(!r.ok)alert('Delete failed');await load()}
$('files').onclick=e=>{const tr=e.target.closest('tr');if(!tr||e.target.tagName==='BUTTON')return;document.querySelectorAll('#files tr').forEach(x=>x.classList.remove('selected'));tr.classList.add('selected')};
function format(n){let u=['B','KB','MB','GB','TB'],i=0,x=n;while(x>=1024&&i<4){x/=1024;i++}return x.toFixed(i?1:0)+' '+u[i]}function setStatus(x){$('status').textContent=x}
$('websiteBtn').onclick=()=>{$('websiteModal').classList.add('open');loadWebsites()};$('websiteCancel').onclick=()=>$('websiteModal').classList.remove('open');async function loadWebsites(){const r=await fetch('/api/websites');if(!r.ok)return;const list=await r.json();$('websiteList').innerHTML=list.length?'<h3>Published websites</h3>':'';for(const x of list){const row=document.createElement('div');row.style.cssText='padding:10px 0;border-bottom:1px solid #d8cbb9';row.innerHTML='<strong></strong><small style="display:block;color:var(--muted)"></small>';row.children[0].textContent=x.domain;row.children[1].textContent='WEBSITE: '+x.folder;const b=document.createElement('button');b.textContent='Unpublish';b.onclick=async()=>{await fetch('/api/websites/'+encodeURIComponent(x.name),{method:'DELETE'});loadWebsites()};const sand=document.createElement('button');sand.textContent=x.in_sandstorm?'✓ In SANDSTORM SEARCH':'Add to SANDSTORM SEARCH';sand.onclick=async()=>{const r=await fetch('/api/websites/'+encodeURIComponent(x.name)+'/sandstorm',{method:'POST'});if(!r.ok)return alert(await r.text());const y=await r.json();sand.textContent=y.in_sandstorm?'✓ In SANDSTORM SEARCH':'Add to SANDSTORM SEARCH'};row.appendChild(sand);row.appendChild(b);$('websiteList').appendChild(row)}}$('websitePublish').onclick=async()=>{const folder=$('websiteFolder').value.trim(),name=$('websiteName').value.trim()||folder.split('/').pop(),domain=$('websiteDomain').value.trim();if(!folder)return alert('Enter the WEBSITE folder.');const r=await fetch('/api/websites',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({folder,name,domain})});if(!r.ok)return alert(await r.text());const x=await r.json();$('websiteDomain').value='';loadWebsites();setStatus('Website published at '+x.domain)};$('uploadBtn').onclick=upload;$('refreshBtn').onclick=load;$('downloadBtn').onclick=()=>{const tr=document.querySelector('#files tr.selected');if(tr)tr.querySelector('button').click();else alert('Select a file first.')};$('deleteBtn').onclick=del;$('vaultBtn').onclick=()=>{$('vaultModal').classList.add('open')};$('searchBtn').onclick=render;$('search').oninput=render;
async function loadConnections(){const r=await fetch('/api/connections');const list=await r.json();const box=$('connectionList');box.innerHTML='';for(const [id,name] of [['google','Google Drive'],['dropbox','Dropbox'],['onedrive','OneDrive']]){const x=list.find(v=>v.provider===id);const row=document.createElement('div');row.style.cssText='display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #d8cbb9';row.innerHTML='<span><strong>'+name+'</strong><small style="display:block;color:var(--muted)">'+(x?'Connected via '+x.mode:'Not connected')+'</small></span>';const b=document.createElement('button');b.textContent=x?'Disconnect':'Connect';b.onclick=async()=>{if(x){await fetch('/api/connections/'+id,{method:'DELETE'});loadConnections()}else location.href='/connect/'+id};row.appendChild(b);box.appendChild(row)}}function openConnections(){loadConnections();$('connectionsModal').classList.add('open')}$('connectionsBtn').onclick=openConnections;$('connectionsClose').onclick=()=>$('connectionsModal').classList.remove('open');$('tokenConnect').onclick=async()=>{const token=$('tokenValue').value.trim();if(!token)return alert('Paste a token first.');const r=await fetch('/api/connections/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({provider:$('tokenProvider').value,token})});if(!r.ok)return alert(await r.text());$('tokenValue').value='';loadConnections();setStatus('Connection saved.')};load().catch(e=>setStatus('Could not load files: '+e.message));
</script></body></html>'''

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=True)
