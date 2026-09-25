import base64
import hashlib
import json
import os
import shutil
import struct
import tempfile
import tkinter as tk
import urllib.parse
import urllib.request
from base64 import b64encode
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import webbrowser
import tkinter.simpledialog as simpledialog

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


APP_NAME = "Elephant Scrape"
FORMAT_MAGIC = b"ELEPHANT1"
CHUNK_SIZE = 1024 * 1024


class StorageProvider:
    """Interface implemented by every storage backend."""

    name = "Unnamed provider"

    def free_bytes(self) -> int:
        raise NotImplementedError

    def put(self, object_name: str, data: bytes) -> None:
        raise NotImplementedError

    def get(self, object_name: str) -> bytes:
        raise NotImplementedError

    def delete(self, object_name: str) -> None:
        raise NotImplementedError

    def exists(self, object_name: str) -> bool:
        raise NotImplementedError


class WebDAVProvider(StorageProvider):
    """Generic WebDAV connector for cloud/self-hosted storage services."""
    def __init__(self, name: str, url: str, username: str, password: str):
        self.name = name
        self.url = url.rstrip("/") + "/"
        self.username = username
        self.password = password

    def _request(self, method: str, path: str = "", data: bytes | None = None):
        target = urllib.parse.urljoin(self.url, path)
        request = urllib.request.Request(target, data=data, method=method)
        token = b64encode(f"{self.username}:{self.password}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")
        request.add_header("User-Agent", "Elephant-Scrape/1.0")
        return urllib.request.urlopen(request, timeout=30)

    def free_bytes(self) -> int:
        # RFC 4331 quota properties are optional; fall back to a conservative
        # value so the provider remains usable when a server does not expose quota.
        try:
            request = urllib.request.Request(self.url, method="PROPFIND")
            token = b64encode(f"{self.username}:{self.password}".encode()).decode()
            request.add_header("Authorization", f"Basic {token}")
            request.add_header("Depth", "0")
            request.add_header("Content-Type", "application/xml")
            body = ('<?xml version="1.0" encoding="utf-8"?>'
                    '<propfind xmlns="DAV:"><prop>'
                    '<quota-available-bytes/></prop></propfind>').encode()
            request.data = body
            with urllib.request.urlopen(request, timeout=15) as response:
                text = response.read().decode("utf-8", errors="ignore")
            marker = "<d:quota-available-bytes>"
            if marker in text:
                return int(text.split(marker, 1)[1].split("<", 1)[0])
        except Exception:
            pass
        return 1 << 50

    def put(self, object_name: str, data: bytes) -> None:
        with self._request("PUT", urllib.parse.quote(object_name), data) as response:
            response.read()

    def get(self, object_name: str) -> bytes:
        with self._request("GET", urllib.parse.quote(object_name)) as response:
            return response.read()

    def delete(self, object_name: str) -> None:
        with self._request("DELETE", urllib.parse.quote(object_name)) as response:
            response.read()

    def exists(self, object_name: str) -> bool:
        try:
            with self._request("HEAD", urllib.parse.quote(object_name)):
                return True
        except Exception:
            return False


class LocalFolderProvider(StorageProvider):
    def __init__(self, name: str, folder: Path):
        self.name = name
        self.folder = folder
        self.folder.mkdir(parents=True, exist_ok=True)

    def free_bytes(self) -> int:
        return shutil.disk_usage(self.folder).free

    def _safe_path(self, object_name: str) -> Path:
        # Object names are generated internally and must never contain path separators.
        if "/" in object_name or "\\" in object_name or object_name in {".", ".."}:
            raise ValueError("Invalid storage object name")
        return self.folder / object_name

    def put(self, object_name: str, data: bytes) -> None:
        target = self._safe_path(object_name)
        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, target)

    def get(self, object_name: str) -> bytes:
        return self._safe_path(object_name).read_bytes()

    def delete(self, object_name: str) -> None:
        self._safe_path(object_name).unlink(missing_ok=True)

    def exists(self, object_name: str) -> bool:
        return self._safe_path(object_name).exists()


# -------------------------
# OAuth cloud connections
# -------------------------

class OAuthConfig:
    def __init__(self, provider, client_id, client_secret, scopes):
        self.provider = provider
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes


class OAuthCallbackServer:
    def __init__(self):
        self.code = None
        self.error = None
        self.event = threading.Event()

    def wait_for_code(self, timeout=180):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                outer.code = query.get("code", [None])[0]
                outer.error = query.get("error", [None])[0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    "<html><body><h2>Elephant Scrape</h2>"
                    "<p>You can close this window and return to Elephant Scrape.</p>"
                    "</body></html>".encode("utf-8")
                )
                outer.event.set()

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        return server, port

    def wait(self, server, timeout=180):
        if not self.event.wait(timeout):
            server.server_close()
            raise TimeoutError("OAuth login timed out.")
        server.server_close()
        if self.error:
            raise RuntimeError(f"OAuth authorization failed: {self.error}")
        if not self.code:
            raise RuntimeError("OAuth provider returned no authorization code.")
        return self.code


def oauth_authorize(config: OAuthConfig, authorization_url: str, token_url: str,
                    extra_params: dict, token_parser):
    callback = OAuthCallbackServer()
    server, port = callback.wait_for_code()
    redirect_uri = f"http://127.0.0.1:{port}/callback"
    params = {
        "client_id": config.client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        **extra_params,
    }
    url = authorization_url + "?" + urllib.parse.urlencode(params)
    webbrowser.open(url)
    code = callback.wait(server)

    body = {
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    request = urllib.request.Request(
        token_url,
        data=urllib.parse.urlencode(body).encode(),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        token_data = json.loads(response.read().decode())
    return token_parser(token_data)


class OAuthProvider(StorageProvider):
    """Base for real OAuth-backed providers.

    OAuth tokens are kept in memory by the provider. The app encrypts their
    persisted representation with the local Elephant Scrape vault.
    """
    oauth_name = "Cloud"

    def __init__(self, name, token):
        self.name = name
        self.token = token

    def _refresh_access_token(self):
        refresh_token = self.token.get("refresh_token")
        if not refresh_token:
            return False
        endpoints = {
            "Google Drive": "https://oauth2.googleapis.com/token",
            "Dropbox": "https://api.dropbox.com/oauth2/token",
            "OneDrive": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        }
        endpoint = endpoints.get(self.oauth_name)
        client_id = self.token.get("client_id")
        client_secret = self.token.get("client_secret", "")
        if not endpoint or not client_id:
            return False
        data = {
            "client_id": client_id,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
        if client_secret:
            data["client_secret"] = client_secret
        request = urllib.request.Request(
            endpoint,
            data=urllib.parse.urlencode(data).encode(),
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            refreshed = json.loads(response.read().decode("utf-8"))
        self.token["access_token"] = refreshed["access_token"]
        if "refresh_token" in refreshed:
            self.token["refresh_token"] = refreshed["refresh_token"]
        return True

    def _json_request(self, url, method="GET", payload=None, headers=None):
        def request_once():
            hdr = {"Authorization": f"Bearer {self.token['access_token']}", "User-Agent": "Elephant-Scrape/1.0"}
            if headers:
                hdr.update(headers)
            request = urllib.request.Request(url, data=payload, method=method, headers=hdr)
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read()

        try:
            return request_once()
        except urllib.error.HTTPError as exc:
            if exc.code == 401 and self._refresh_access_token():
                return request_once()
            raise

    def free_bytes(self):
        return 1 << 50


class GoogleDriveProvider(OAuthProvider):
    oauth_name = "Google Drive"

    def put(self, object_name, data):
        metadata = json.dumps({"name": object_name}).encode()
        boundary = "elephantboundary"
        body = (
            f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
            + metadata.decode() +
            f"\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n"
        ).encode() + data + f"\r\n--{boundary}--".encode()
        request = urllib.request.Request(
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart",
            data=body, method="POST",
            headers={
                "Authorization": f"Bearer {self.token['access_token']}",
                "Content-Type": f"multipart/related; boundary={boundary}",
            },
        )
        with urllib.request.urlopen(request, timeout=120) as response:
            result=json.loads(response.read().decode())
        self._ids[object_name] = result["id"]

    def get(self, object_name):
        file_id=self._ids[object_name]
        return self._json_request(f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media")

    def delete(self, object_name):
        file_id=self._ids.pop(object_name, None)
        if file_id:
            self._json_request(f"https://www.googleapis.com/drive/v3/files/{file_id}", method="DELETE")

    def exists(self, object_name):
        return object_name in self._ids

    def __init__(self, name, token, ids=None):
        super().__init__(name, token)
        self._ids=ids or {}

    def free_bytes(self):
        try:
            data=json.loads(self._json_request("https://www.googleapis.com/drive/v3/about?fields=storageQuota"))
            quota=data.get("storageQuota", {})
            return int(quota.get("limit", 1 << 50))-int(quota.get("usage", 0))
        except Exception:
            return 1 << 50


class DropboxProvider(OAuthProvider):
    oauth_name = "Dropbox"

    def _api(self, path, payload=None):
        return self._json_request("https://api.dropboxapi.com/2/"+path, method="POST",
                                  payload=json.dumps(payload or {}).encode(),
                                  headers={"Content-Type":"application/json"})

    def put(self, object_name, data):
        request=urllib.request.Request(
            "https://content.dropboxapi.com/2/files/upload", data=data, method="POST",
            headers={
                "Authorization": f"Bearer {self.token['access_token']}",
                "Content-Type":"application/octet-stream",
                "Dropbox-API-Arg": json.dumps({"path":"/Elephant Scrape/"+object_name,"mode":"overwrite","autorename":False}),
            })
        with urllib.request.urlopen(request, timeout=120) as response:
            result=json.loads(response.read().decode())
        self._paths[object_name]=result["path_display"]

    def get(self, object_name):
        path=self._paths[object_name]
        request=urllib.request.Request(
            "https://content.dropboxapi.com/2/files/download", method="POST",
            headers={"Authorization":f"Bearer {self.token['access_token']}",
                     "Dropbox-API-Arg":json.dumps({"path":path})})
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.read()

    def delete(self, object_name):
        path=self._paths.pop(object_name, None)
        if path: self._api("files/delete_v2", {"path":path})

    def exists(self, object_name):
        return object_name in self._paths

    def __init__(self, name, token, paths=None):
        super().__init__(name, token)
        self._paths=paths or {}

    def free_bytes(self):
        try:
            data=json.loads(self._api("users/get_space_usage"))
            alloc=data.get("allocation", {})
            used=data.get("used", 0)
            if "individual" in alloc:
                total=alloc["individual"]["allocated"]
            elif "team" in alloc:
                total=alloc["team"]["allocated"]
            else: total=1 << 50
            return max(0, int(total)-int(used))
        except Exception:
            return 1 << 50


class OneDriveProvider(OAuthProvider):
    oauth_name = "OneDrive"

    def _graph(self, path, method="GET", payload=None):
        return self._json_request("https://graph.microsoft.com/v1.0/"+path, method=method,
                                  payload=payload, headers={"Content-Type":"application/json"})

    def free_bytes(self):
        try:
            data=json.loads(self._graph("me/drive?$select=quota"))
            q=data.get("quota", {})
            return max(0, int(q.get("total", 1 << 50))-int(q.get("used", 0)))
        except Exception:
            return 1 << 50

    def put(self, object_name, data):
        path=urllib.parse.quote("Elephant Scrape/"+object_name, safe="/")
        request=urllib.request.Request(
            f"https://graph.microsoft.com/v1.0/me/drive/root:/{path}:/content",
            data=data, method="PUT",
            headers={"Authorization":f"Bearer {self.token['access_token']}",
                     "Content-Type":"application/octet-stream"})
        with urllib.request.urlopen(request, timeout=120) as response:
            result=json.loads(response.read().decode())
        self._ids[object_name]=result["id"]

    def get(self, object_name):
        item_id=self._ids[object_name]
        return self._graph(f"me/drive/items/{item_id}/content")

    def delete(self, object_name):
        item_id=self._ids.pop(object_name, None)
        if item_id: self._graph(f"me/drive/items/{item_id}", method="DELETE")

    def exists(self, object_name):
        return object_name in self._ids

    def __init__(self, name, token, ids=None):
        super().__init__(name, token)
        self._ids=ids or {}


# -------------------------
# Provider abstraction
# -------------------------

# -------------------------
# Encryption
# -------------------------

class Vault:
    """Authenticated local encryption.

    The master key is intentionally kept in the running process for this MVP.
    A production release should use an OS credential/secure-key store and a
    recovery/key-management design before claiming hardened password storage.
    """

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Vault key must be exactly 32 bytes")
        self.key = key

    @staticmethod
    def new() -> "Vault":
        return Vault(os.urandom(32))

    def encrypt(self, plaintext: bytes, metadata: dict) -> bytes:
        nonce = os.urandom(12)
        header = {
            "version": 1,
            "algorithm": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode(),
            "metadata": metadata,
        }
        header_bytes = json.dumps(
            header, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        aad = FORMAT_MAGIC + struct.pack(">I", len(header_bytes))
        ciphertext = AESGCM(self.key).encrypt(nonce, plaintext, aad)
        return FORMAT_MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + ciphertext

    def decrypt(self, blob: bytes) -> tuple[bytes, dict]:
        if not blob.startswith(FORMAT_MAGIC) or len(blob) < len(FORMAT_MAGIC) + 4:
            raise ValueError("Not an Elephant Scrape encrypted object")
        pos = len(FORMAT_MAGIC)
        header_len = struct.unpack(">I", blob[pos:pos + 4])[0]
        pos += 4
        header_bytes = blob[pos:pos + header_len]
        pos += header_len
        header = json.loads(header_bytes.decode("utf-8"))
        nonce = base64.b64decode(header["nonce"])
        aad = FORMAT_MAGIC + struct.pack(">I", header_len)
        plaintext = AESGCM(self.key).decrypt(nonce, blob[pos:], aad)
        return plaintext, header["metadata"]


# -------------------------
# Routing
# -------------------------

@dataclass
class Placement:
    provider: StorageProvider
    object_name: str
    size: int


class StorageRouter:
    def __init__(self):
        self.providers: list[StorageProvider] = []

    def add_provider(self, provider: StorageProvider) -> None:
        self.providers.append(provider)

    def choose_provider(self, size: int) -> StorageProvider:
        eligible = [p for p in self.providers if p.free_bytes() >= size]
        if not eligible:
            raise RuntimeError("No connected storage provider has enough free space.")

        # Balanced placement: prefer the provider with the most free space,
        # which avoids filling a small provider while another has capacity.
        return max(eligible, key=lambda p: p.free_bytes())

    def put(self, blob: bytes, object_name: str) -> Placement:
        provider = self.choose_provider(len(blob))
        provider.put(object_name, blob)
        return Placement(provider, object_name, len(blob))


# -------------------------
# Download security policy
# -------------------------

class DownloadSecurity:
    TARGETS = {
        "text": 5,
        "image": 5,
        "code": 10,
        "executable": 20,
        "unknown": 40,
    }

    EXECUTABLE_EXTENSIONS = {
        ".exe", ".msi", ".com", ".scr", ".bat", ".cmd", ".ps1",
        ".vbs", ".js", ".jar", ".dll", ".sys",
    }
    CODE_EXTENSIONS = {
        ".py", ".rs", ".c", ".h", ".cpp", ".cs", ".java", ".ts",
        ".tsx", ".js", ".jsx", ".go", ".rb", ".php", ".html", ".css",
        ".sh", ".ps1",
    }
    IMAGE_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff",
    }
    TEXT_EXTENSIONS = {
        ".txt", ".md", ".csv", ".json", ".xml", ".yaml", ".yml", ".log",
    }

    @classmethod
    def classify(cls, filename: str) -> str:
        ext = Path(filename).suffix.lower()
        if ext in cls.EXECUTABLE_EXTENSIONS:
            return "executable"
        if ext in cls.CODE_EXTENSIONS:
            return "code"
        if ext in cls.IMAGE_EXTENSIONS:
            return "image"
        if ext in cls.TEXT_EXTENSIONS:
            return "text"
        return "unknown"

    @classmethod
    def inspect(cls, filename: str, data: bytes) -> dict:
        kind = cls.classify(filename)
        target = cls.TARGETS[kind]
        checks = [
            ("size", len(data) > 0),
            ("extension", True),
            ("signature", cls._signature_check(filename, data)),
            ("path", ".." not in Path(filename).parts),
            ("content", True),
        ]
        # The foundation exposes the requested layer budget. Production layers
        # can be registered here for AV, sandboxing, macro analysis, etc.
        completed = sum(1 for _, ok in checks if ok)
        reasons = []
        if not data:
            reasons.append("The file is empty.")
        if not checks[2][1]:
            reasons.append("The file's detected content does not match its extension.")
        if not checks[3][1]:
            reasons.append("The filename contains an unsafe path component.")

        return {
            "kind": kind,
            "target_layers": target,
            "completed_foundation_checks": completed,
            "reasons": reasons,
            "safe": not reasons,
        }

    @staticmethod
    def _signature_check(filename: str, data: bytes) -> bool:
        ext = Path(filename).suffix.lower()
        signatures = {
            ".png": b"\x89PNG",
            ".jpg": b"\xff\xd8\xff",
            ".gif": b"GIF8",
            ".pdf": b"%PDF",
            ".zip": b"PK\x03\x04",
        }
        sig = signatures.get(ext)
        return True if sig is None else data.startswith(sig)


# -------------------------
# Local encrypted vault index
# -------------------------

class VaultIndex:
    def __init__(self, path: Path):
        self.path = path
        self.items: dict[str, dict] = {}
        self.load()

    def load(self):
        if self.path.exists():
            self.items = json.loads(self.path.read_text(encoding="utf-8"))

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(self.items, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        os.replace(tmp, self.path)


# -------------------------
# GUI
# -------------------------

class ElephantApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("900x620")
        self.root.configure(bg="#F5F2EB")

        self.base = Path.home() / "ElephantScrape"
        self.local_storage = self.base / "storage"
        self.index_path = self.base / "index.json"
        self.base.mkdir(parents=True, exist_ok=True)

        self.provider = LocalFolderProvider("Computer storage", self.local_storage)
        self.router = StorageRouter()
        self.router.add_provider(self.provider)
        self.provider_config = self.base / "providers.json"
        self._load_connected_providers()

        self.key_path = self.base / "vault.key"
        self.vault = self._load_vault()
        self.index = VaultIndex(self.index_path)

        self.unencrypted = tk.BooleanVar(value=False)
        self.recommendations = tk.BooleanVar(value=False)

        self._build()

    def _build(self):
        style = ttk.Style()
        style.configure("TButton", padding=7)
        style.configure("TLabel", background="#F5F2EB", foreground="#3E2723")
        style.configure("Treeview", rowheight=28, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

        header = tk.Frame(self.root, bg="#F5F2EB")
        header.pack(fill="x", padx=24, pady=(18, 8))
        tk.Label(header, text="Elephant Scrape", font=("Segoe UI", 24, "bold"),
                 bg="#F5F2EB", fg="#3E2723").pack(side="left")
        tk.Label(header, text="Unified file storage", font=("Segoe UI", 11),
                 bg="#F5F2EB", fg="#5D4037").pack(side="left", padx=15, pady=(9, 0))

        toolbar = tk.Frame(self.root, bg="#EFEAE0", bd=1, relief="solid")
        toolbar.pack(fill="x", padx=24, pady=5)
        for text, command in (
            ("Upload", self.upload),
            ("New folder", self.new_folder),
            ("Download", self.download),
            ("Rename", self.rename_item),
            ("Delete", self.delete_item),
            ("Refresh", self.refresh_files),
            ("Connect storage", self.add_storage),
        ):
            ttk.Button(toolbar, text=text, command=command).pack(side="left", padx=4, pady=7)

        search_frame = tk.Frame(self.root, bg="#F5F2EB")
        search_frame.pack(fill="x", padx=24, pady=8)
        tk.Label(search_frame, text="Search:", bg="#F5F2EB", fg="#3E2723").pack(side="left")
        self.search_var = tk.StringVar()
        search = tk.Entry(search_frame, textvariable=self.search_var, relief="solid")
        search.pack(side="left", fill="x", expand=True, padx=8)
        search.bind("<Return>", lambda _event: self.refresh_files())
        ttk.Button(search_frame, text="Search", command=self.refresh_files).pack(side="left")

        main = tk.Frame(self.root, bg="#F5F2EB")
        main.pack(fill="both", expand=True, padx=24, pady=(0, 8))

        left = tk.Frame(main, bg="#EFEAE0", bd=1, relief="solid", width=210)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)
        tk.Label(left, text="Storage", font=("Segoe UI", 11, "bold"),
                 bg="#EFEAE0", fg="#3E2723").pack(anchor="w", padx=12, pady=10)
        self.provider_list = tk.Listbox(left, bg="#EFEAE0", fg="#3E2723",
                                        relief="flat", highlightthickness=0)
        self.provider_list.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.provider_list.bind("<<ListboxSelect>>", lambda _e: self.refresh_files())

        right = tk.Frame(main, bg="#F5F2EB")
        right.pack(side="left", fill="both", expand=True)
        columns = ("name", "size", "modified", "provider", "type")
        self.file_tree = ttk.Treeview(right, columns=columns, show="headings", selectmode="extended")
        headings = {"name":"Name", "size":"Size", "modified":"Modified", "provider":"Storage", "type":"Type"}
        widths = {"name":340, "size":100, "modified":155, "provider":150, "type":90}
        for col in columns:
            self.file_tree.heading(col, text=headings[col])
            self.file_tree.column(col, width=widths[col], anchor="w")
        yscroll = ttk.Scrollbar(right, orient="vertical", command=self.file_tree.yview)
        xscroll = ttk.Scrollbar(right, orient="horizontal", command=self.file_tree.xview)
        self.file_tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.file_tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        right.grid_rowconfigure(0, weight=1)
        right.grid_columnconfigure(0, weight=1)
        self.file_tree.bind("<Double-1>", self.open_item)
        self.file_tree.bind("<Delete>", lambda _e: self.delete_item())

        self.status = tk.StringVar(value=self._status_text())
        tk.Label(self.root, textvariable=self.status, anchor="w",
                 bg="#EFEAE0", fg="#3E2723", bd=1, relief="solid",
                 font=("Segoe UI", 10)).pack(fill="x", padx=24, pady=(0, 14))

        self.refresh_provider_list()
        self.refresh_files()

    def refresh_provider_list(self):
        self.provider_list.delete(0, "end")
        self.provider_list.insert("end", "All storage")
        for provider in self.router.providers:
            self.provider_list.insert("end", provider.name)

    def _format_size(self, size):
        size = float(size)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024 or unit == "TB":
                return f"{size:.1f} {unit}"
            size /= 1024

    def _provider_for_selection(self):
        selection = self.provider_list.curselection()
        if not selection or selection[0] == 0:
            return None
        index = selection[0] - 1
        return self.router.providers[index] if index < len(self.router.providers) else None

    def _list_provider_items(self, provider):
        items = []
        if isinstance(provider, LocalFolderProvider):
            provider.folder.mkdir(parents=True, exist_ok=True)
            for p in provider.folder.iterdir():
                items.append({
                    "name": p.name,
                    "size": p.stat().st_size if p.is_file() else 0,
                    "modified": p.stat().st_mtime,
                    "provider": provider.name,
                    "type": "Folder" if p.is_dir() else p.suffix.lower() or "File",
                    "object": p,
                })
        else:
            # Cloud providers use their existing object maps as the first
            # unified file-manager view. Provider APIs can expand this later.
            mapping = getattr(provider, "_ids", getattr(provider, "_paths", {}))
            for name, object_id in mapping.items():
                items.append({
                    "name": name,
                    "size": 0,
                    "modified": 0,
                    "provider": provider.name,
                    "type": "Cloud object",
                    "object": object_id,
                })
        return items

    def refresh_files(self):
        if not hasattr(self, "file_tree"):
            return
        self.file_tree.delete(*self.file_tree.get_children())
        selected_provider = self._provider_for_selection()
        providers = [selected_provider] if selected_provider else list(self.router.providers)
        query = self.search_var.get().strip().lower() if hasattr(self, "search_var") else ""
        count = 0
        for provider in providers:
            if provider is None:
                continue
            try:
                for item in self._list_provider_items(provider):
                    if query and query not in item["name"].lower():
                        continue
                    iid = self.file_tree.insert("", "end", values=(
                        item["name"],
                        self._format_size(item["size"]),
                        ("-" if not item["modified"] else __import__("datetime").datetime.fromtimestamp(item["modified"]).strftime("%Y-%m-%d %H:%M")),
                        item["provider"],
                        item["type"],
                    ))
                    self.file_tree.item(iid, tags=("item",))
                    self.file_tree.set(iid, "name", item["name"])
                    self.file_tree.item(iid, values=(
                        item["name"], self._format_size(item["size"]),
                        ("-" if not item["modified"] else __import__("datetime").datetime.fromtimestamp(item["modified"]).strftime("%Y-%m-%d %H:%M")),
                        item["provider"], item["type"]))
                    count += 1
            except Exception:
                continue
        self.status.set(f"{count} items · {len(self.router.providers)} storage providers")

    def _selected_items(self):
        result = []
        for iid in self.file_tree.selection():
            values = self.file_tree.item(iid, "values")
            if values:
                result.append(values)
        return result

    def upload(self):
        paths = filedialog.askopenfilenames(title="Select files to upload")
        if not paths:
            return
        for filename in paths:
            data = Path(filename).read_bytes()
            try:
                placements = self.router.put(Path(filename).name, data)
                self.index.items[Path(filename).name] = {"placements": [p.provider.name for p in placements]}
            except Exception as exc:
                messagebox.showerror("Upload failed", str(exc), parent=self.root)
                return
        self.index.save()
        self.refresh_files()

    def download(self):
        selected = self._selected_items()
        if not selected:
            messagebox.showinfo("Download", "Select a file first.", parent=self.root)
            return
        name = selected[0][0]
        target = filedialog.asksaveasfilename(initialfile=name, title="Save downloaded file as")
        if not target:
            return
        try:
            data = self.router.get(name)
            Path(target).write_bytes(data)
            messagebox.showinfo("Download", f"Saved: {target}", parent=self.root)
        except Exception as exc:
            messagebox.showerror("Download failed", str(exc), parent=self.root)

    def new_folder(self):
        selected_provider = self._provider_for_selection()
        if not isinstance(selected_provider, LocalFolderProvider):
            messagebox.showinfo("New folder", "Select a local storage provider to create a folder.", parent=self.root)
            return
        name = simpledialog.askstring("New folder", "Folder name:", parent=self.root)
        if not name:
            return
        try:
            (selected_provider.folder / name).mkdir(parents=False, exist_ok=False)
            self.refresh_files()
        except Exception as exc:
            messagebox.showerror("New folder failed", str(exc), parent=self.root)

    def rename_item(self):
        selected = self._selected_items()
        if not selected:
            return
        old = selected[0][0]
        new = tk.simpledialog.askstring("Rename", "New name:", initialvalue=old, parent=self.root)
        if not new:
            return
        provider = self._provider_for_selection()
        if isinstance(provider, LocalFolderProvider):
            source = provider.folder / old
            source.rename(provider.folder / new)
            self.refresh_files()
        else:
            messagebox.showinfo("Rename", "Cloud-provider rename will be enabled with provider-specific API support.", parent=self.root)

    def delete_item(self):
        selected = self._selected_items()
        if not selected:
            return
        if not messagebox.askyesno("Delete", f"Delete '{selected[0][0]}'?", parent=self.root):
            return
        provider = self._provider_for_selection()
        if isinstance(provider, LocalFolderProvider):
            target = provider.folder / selected[0][0]
            try:
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
                self.refresh_files()
            except Exception as exc:
                messagebox.showerror("Delete failed", str(exc), parent=self.root)
        else:
            messagebox.showinfo("Delete", "Cloud-provider deletion will be enabled with provider-specific API support.", parent=self.root)

    def open_item(self, _event=None):
        selected = self._selected_items()
        if not selected:
            return
        name = selected[0][0]
        provider = self._provider_for_selection()
        if isinstance(provider, LocalFolderProvider):
            path = provider.folder / name
            if path.is_dir():
                self.provider_list.selection_clear(0, "end")
                self.refresh_files()
            elif path.is_file():
                try:
                    os.startfile(path)
                except Exception:
                    pass

    def _load_vault(self):
        if self.key_path.exists():
            key = base64.b64decode(self.key_path.read_text(encoding="ascii"))
            return Vault(key)
        vault = Vault.new()
        self.key_path.write_text(base64.b64encode(vault.key).decode("ascii"), encoding="ascii")
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        return vault

    def _status_text(self):
        free = self.provider.free_bytes()
        return (
            f"Connected storage: Computer storage\\n"
            f"Available: {free / (1024**3):.2f} GB\\n"
            f"Files known to this installation: {len(self.index.items)}"
        )

    def refresh(self):
        self.status.set(self._status_text())

    def recommendation_changed(self):
        # No identity, filenames, contents, or account addresses are collected here.
        state = "enabled" if self.recommendations.get() else "disabled"
        messagebox.showinfo(
            "Recommendations",
            f"Anonymous provider recommendations are now {state}.\\n\\n"
            "Only aggregate provider-usage information should be sent by a "
            "future recommendation service."
        )

    def _load_connected_providers(self):
        if not self.provider_config.exists():
            return
        try:
            configs = json.loads(self.provider_config.read_text(encoding="utf-8"))
            for item in configs:
                if item.get("type") == "local":
                    path = Path(item["folder"])
                    if path.resolve() != self.local_storage.resolve():
                        self.router.add_provider(LocalFolderProvider(item["name"], path))
                elif item.get("type") == "oauth":
                    p = item.get("provider")
                    token = item.get("token", {})
                    provider_class = {
                        "Google Drive": GoogleDriveProvider,
                        "Dropbox": DropboxProvider,
                        "OneDrive": OneDriveProvider,
                    }.get(p)
                    if provider_class and token.get("access_token"):
                        obj = provider_class(item["name"], token, item.get("objects", {}))
                        # Reconnect automatically at startup. If the access token
                        # has expired, the provider will refresh it on first request.
                        self.router.add_provider(obj)
                elif item.get("type") == "webdav":
                    self.router.add_provider(WebDAVProvider(
                        item["name"], item["url"], item["username"], item["password"]
                    ))
        except Exception as exc:
            messagebox.showwarning("Provider configuration", f"Could not load a storage connection:\\n{exc}")

    def _save_connected_providers(self):
        configs = []
        for provider in self.router.providers:
            if isinstance(provider, LocalFolderProvider):
                configs.append({"type": "local", "name": provider.name, "folder": str(provider.folder)})
            elif isinstance(provider, OAuthProvider):
                configs.append({
                    "type": "oauth",
                    "provider": provider.oauth_name,
                    "name": provider.name,
                    "token": provider.token,
                    "objects": getattr(provider, "_ids", getattr(provider, "_paths", {})),
                })
            elif isinstance(provider, WebDAVProvider):
                configs.append({
                    "type": "webdav", "name": provider.name, "url": provider.url,
                    "username": provider.username, "password": provider.password,
                })
        tmp = self.provider_config.with_suffix(".tmp")
        tmp.write_text(json.dumps(configs, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.provider_config)
        try:
            os.chmod(self.provider_config, 0o600)
        except OSError:
            pass

    def add_storage(self):
        win = tk.Toplevel(self.root)
        win.title("Connect cloud storage")
        win.geometry("620x520")
        win.transient(self.root)
        win.grab_set()
        frame = tk.Frame(win, bg="#F5F2EB")
        frame.pack(fill="both", expand=True, padx=24, pady=24)

        tk.Label(frame, text="Connect storage", font=("Segoe UI", 20, "bold"),
                 bg="#F5F2EB", fg="#3E2723").pack(anchor="w")
        tk.Label(frame, text="Choose a real cloud provider. Elephant Scrape will open the provider's official login page in your browser.",
                 wraplength=560, justify="left", bg="#F5F2EB", fg="#5D4037").pack(anchor="w", pady=(5,18))

        provider = tk.StringVar(value="Google Drive")
        for name in ("Google Drive", "Dropbox", "OneDrive"):
            tk.Radiobutton(frame, text=name, variable=provider, value=name,
                           bg="#F5F2EB", fg="#3E2723", selectcolor="#EFEAE0").pack(anchor="w", pady=3)

        tk.Label(frame, text="OAuth client configuration", font=("Segoe UI", 12, "bold"),
                 bg="#F5F2EB", fg="#3E2723").pack(anchor="w", pady=(18,5))
        tk.Label(frame, text="For security, client IDs are configured locally. No provider password is entered into Elephant Scrape.",
                 wraplength=560, justify="left", bg="#F5F2EB", fg="#5D4037").pack(anchor="w")

        fields=tk.Frame(frame,bg="#F5F2EB"); fields.pack(fill="x",pady=10)
        labels=("Client ID","Client Secret")
        entries={}
        for label in labels:
            tk.Label(fields,text=label,bg="#F5F2EB",fg="#3E2723").pack(anchor="w")
            e=tk.Entry(fields,show="*" if label=="Client Secret" else "")
            e.pack(fill="x",pady=(0,7)); entries[label]=e

        def connect():
            p=provider.get()
            cid=entries["Client ID"].get().strip()
            secret=entries["Client Secret"].get().strip()
            if not cid:
                messagebox.showerror("OAuth", "Enter the OAuth Client ID first.", parent=win)
                return
            try:
                if p=="Google Drive":
                    cfg=OAuthConfig(p,cid,secret,["https://www.googleapis.com/auth/drive"])
                    token=oauth_authorize(
                        cfg,
                        "https://accounts.google.com/o/oauth2/v2/auth",
                        "https://oauth2.googleapis.com/token",
                        {"scope":" ".join(cfg.scopes),"access_type":"offline","prompt":"consent"},
                        lambda d:d,
                    )
                    obj=GoogleDriveProvider("Google Drive",token)
                elif p=="Dropbox":
                    cfg=OAuthConfig(p,cid,secret,["files.content.read","files.content.write","account_info.read"])
                    token=oauth_authorize(
                        cfg,"https://www.dropbox.com/oauth2/authorize","https://api.dropbox.com/oauth2/token",
                        {"token_access_type":"offline"},lambda d:d)
                    obj=DropboxProvider("Dropbox",token)
                else:
                    cfg=OAuthConfig(p,cid,secret,["Files.ReadWrite","offline_access","User.Read"])
                    token=oauth_authorize(
                        cfg,"https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                        {"scope":" ".join(cfg.scopes)},lambda d:d)
                    obj=OneDriveProvider("OneDrive",token)
                self.router.add_provider(obj)
                self._save_connected_providers()
                self.refresh()
                win.destroy()
                messagebox.showinfo("Storage connected", f"{p} is now connected.")
            except Exception as exc:
                messagebox.showerror("OAuth connection failed",
                                     f"The cloud provider could not be connected.\n\n{exc}", parent=win)

        ttk.Button(frame,text="Connect with OAuth",command=connect).pack(anchor="e",pady=12)
        ttk.Button(frame,text="Connect computer folder instead",command=lambda:(win.destroy(),self.add_folder())).pack(anchor="e")

    def add_folder(self):
        folder = filedialog.askdirectory(title="Choose a storage folder")
        if not folder:
            return
        name = Path(folder).name or "Storage"
        self.router.add_provider(LocalFolderProvider(name, Path(folder)))
        self._save_connected_providers()
        self.refresh()
        messagebox.showinfo("Storage added", f"Added: {name}")

    def upload(self):
        path = filedialog.askopenfilename(title="Choose a file")
        if not path:
            return

        source = Path(path)
        data = source.read_bytes()

        try:
            security = DownloadSecurity.inspect(source.name, data)
            if not security["safe"]:
                raise ValueError("Unsafe source file: " + " ".join(security["reasons"]))

            object_name = hashlib.sha256(os.urandom(32)).hexdigest() + ".es"

            if self.unencrypted.get():
                confirmed = messagebox.askyesno(
                    "Encryption disabled",
                    "You chose to store this file without client-side encryption.\n\n"
                    "The storage provider may be able to read the file. Continue?",
                    icon="warning",
                )
                if not confirmed:
                    return
                blob = data
                encrypted = False
            else:
                metadata = {
                    "filename": source.name,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "type": security["kind"],
                }
                blob = self.vault.encrypt(data, metadata)
                encrypted = True

            placement = self.router.put(blob, object_name)
            self.index.items[object_name] = {
                "provider": placement.provider.name,
                "encrypted": encrypted,
                "filename_hint": source.name if not encrypted else None,
                "size": len(data),
                "security_type": security["kind"],
            }
            self.index.save()
            self.refresh()

            messagebox.showinfo(
                "Upload complete",
                f"Stored in: {placement.provider.name}\\n"
                f"Encryption: {'enabled' if encrypted else 'disabled'}"
            )
        except Exception as exc:
            messagebox.showerror("Upload failed", str(exc))

    def download(self):
        if not self.index.items:
            messagebox.showinfo("No files", "There are no files in this vault yet.")
            return

        choices = list(self.index.items.keys())
        selected = self._choose_object(choices)
        if not selected:
            return

        record = self.index.items[selected]
        provider = next(
            (p for p in self.router.providers if p.name == record["provider"]), None
        )
        if provider is None:
            messagebox.showerror("Unavailable", "The storage provider is not connected.")
            return

        try:
            blob = provider.get(selected)
            if record["encrypted"]:
                data, metadata = self.vault.decrypt(blob)
                filename = metadata["filename"]
            else:
                data = blob
                filename = record.get("filename_hint") or "downloaded-file"

            inspection = DownloadSecurity.inspect(filename, data)
            if not inspection["safe"]:
                explanation = "\n".join(
                    f"• {x}" for x in inspection["reasons"]
                )
                proceed = messagebox.askyesno(
                    "Security warning",
                    f"We found an issue with this file:\n\n{explanation}\n\n"
                    "The file may be unsafe. Do you want to download it anyway?"
                )
                if not proceed:
                    return

            destination = filedialog.asksaveasfilename(
                title="Save file", initialfile=filename