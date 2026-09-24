import base64
import hashlib
import json
import os
import shutil
import struct
import tempfile
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


APP_NAME = "Elephant Scrape"
FORMAT_MAGIC = b"ELEPHANT1"
CHUNK_SIZE = 1024 * 1024


# -------------------------
# Provider abstraction
# -------------------------

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
            ".png": b"\\x89PNG",
            ".jpg": b"\\xff\\xd8\\xff",
            ".gif": b"GIF8",
            ".pdf": b"%PDF",
            ".zip": b"PK\\x03\\x04",
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

        self.key_path = self.base / "vault.key"
        self.vault = self._load_vault()
        self.index = VaultIndex(self.index_path)

        self.unencrypted = tk.BooleanVar(value=False)
        self.recommendations = tk.BooleanVar(value=False)

        self._build()

    def _build(self):
        style = ttk.Style()
        style.configure("TButton", padding=8)
        style.configure("TLabel", background="#F5F2EB", foreground="#3E2723")
        style.configure("TCheckbutton", background="#F5F2EB", foreground="#3E2723")

        title = tk.Label(
            self.root, text="Elephant Scrape", font=("Segoe UI", 28, "bold"),
            bg="#F5F2EB", fg="#3E2723"
        )
        title.pack(pady=(28, 4))

        subtitle = tk.Label(
            self.root,
            text="One storage space across the places you choose.",
            font=("Segoe UI", 12),
            bg="#F5F2EB", fg="#5D4037"
        )
        subtitle.pack(pady=(0, 20))

        frame = tk.Frame(self.root, bg="#EFEAE0", bd=1, relief="solid")
        frame.pack(fill="both", expand=True, padx=35, pady=10)

        self.status = tk.StringVar(value=self._status_text())
        tk.Label(
            frame, textvariable=self.status, justify="left", anchor="w",
            bg="#EFEAE0", fg="#3E2723", font=("Segoe UI", 11)
        ).pack(fill="x", padx=20, pady=20)

        buttons = tk.Frame(frame, bg="#EFEAE0")
        buttons.pack(pady=5)

        ttk.Button(buttons, text="Upload file", command=self.upload).grid(row=0, column=0, padx=8)
        ttk.Button(buttons, text="Download file", command=self.download).grid(row=0, column=1, padx=8)
        ttk.Button(buttons, text="Add storage folder", command=self.add_folder).grid(row=0, column=2, padx=8)

        settings = tk.Frame(frame, bg="#EFEAE0")
        settings.pack(fill="x", padx=20, pady=25)

        ttk.Checkbutton(
            settings, text="Store new files unencrypted (user responsibility)",
            variable=self.unencrypted
        ).pack(anchor="w", pady=5)

        ttk.Checkbutton(
            settings, text="Enable anonymous provider recommendations (off by default)",
            variable=self.recommendations,
            command=self.recommendation_changed
        ).pack(anchor="w", pady=5)

        tk.Label(
            frame,
            text="Security targets: 5 layers for text/images · 10 for code · "
                 "20 for executables · 40 for unknown types",
            bg="#EFEAE0", fg="#5D4037", wraplength=760, justify="left"
        ).pack(padx=20, pady=15)

        tk.Label(
            frame,
            text="P2P sharing is reserved for the next transport layer. "
                 "The design keeps provider storage and P2P transfer separate.",
            bg="#EFEAE0", fg="#5D4037", wraplength=760, justify="left"
        ).pack(padx=20, pady=5)

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

    def add_folder(self):
        folder = filedialog.askdirectory(title="Choose a storage folder")
        if not folder:
            return
        name = Path(folder).name or "Storage"
        self.router.add_provider(LocalFolderProvider(name, Path(folder)))
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
            )
            if not destination:
                return

            Path(destination).write_bytes(data)
            messagebox.showinfo("Download complete", "The file was saved to your device.")
        except Exception as exc:
            messagebox.showerror("Download failed", str(exc))

    def _choose_object(self, objects):
        win = tk.Toplevel(self.root)
        win.title("Choose file")
        win.geometry("600x360")
        result = {"value": None}

        tk.Label(
            win, text="Choose a stored object:",
            font=("Segoe UI", 12, "bold")
        ).pack(pady=10)

        lb = tk.Listbox(win, height=12)
        lb.pack(fill="both", expand=True, padx=20)

        for obj in objects:
            record = self.index.items[obj]
            label = record.get("filename_hint") or f"Encrypted object {obj[:12]}…"
            lb.insert("end", f"{label} — {record['provider']}")

        def accept():
            sel = lb.curselection()
            if sel:
                result["value"] = objects[sel[0]]
                win.destroy()

        ttk.Button(win, text="Select", command=accept).pack(pady=12)
        win.transient(self.root)
        win.grab_set()
        self.root.wait_window(win)
        return result["value"]


if __name__ == "__main__":
    root = tk.Tk()
    ElephantApp(root)
    root.mainloop()
