# Password Vault (Tkinter) with single-file AES-GCM encryption and Scrypt KDF
# Requirements: Python 3.9+, cryptography
#   pip install cryptography

import json
import os
import secrets
import struct
import sys
from cryptography import __version__ as cryptography_version
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple, List
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Debug prints (optional, can remove after confirming it works)
print("Python executable:", sys.executable)
print("cryptography version:", cryptography_version)

# ------------------------- Vault storage and crypto -------------------------

HEADER_MAGIC = b"PWSAFE1"  # 7 bytes
VERSION = 1
KDF_ID_SCRYPT = 1
AEAD_ID_AESGCM = 1

HEADER_FMT = "!7sBBBBHH"
HEADER_STATIC_SIZE = struct.calcsize(HEADER_FMT)  # without salt

DEFAULT_SCRYPT_N_LOG2 = 14  # 2**14 = 16384
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
SALT_LEN = 16
NONCE_LEN = 12  # AESGCM standard nonce length
KEY_LEN = 32    # AES-256-GCM

@dataclass
class VaultData:
    entries: Dict[str, Dict[str, str]] = field(default_factory=dict)
    created: float = field(default_factory=lambda: time.time())
    modified: float = field(default_factory=lambda: time.time())

class VaultError(Exception):
    pass

class Vault:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.header_bytes: Optional[bytes] = None
        self.kdf_params: Tuple[int, int, int] = (DEFAULT_SCRYPT_N_LOG2, DEFAULT_SCRYPT_R, DEFAULT_SCRYPT_P)
        self.salt: Optional[bytes] = None
        self.data: VaultData = VaultData()

    @staticmethod
    def derive_key_scrypt(password: str, salt: bytes, n_log2: int, r: int, p: int) -> bytes:
        kdf = Scrypt(salt=salt, length=KEY_LEN, n=1 << n_log2, r=r, p=p)
        return kdf.derive(password.encode("utf-8"))

    def build_header(self, salt: bytes, kdf_params: Tuple[int, int, int]) -> bytes:
        n_log2, r, p = kdf_params
        header_wo_salt = struct.pack(
            HEADER_FMT,
            HEADER_MAGIC,
            VERSION,
            KDF_ID_SCRYPT,
            AEAD_ID_AESGCM,
            len(salt),
            n_log2,
            r,
            p,
        )
        return header_wo_salt + salt

    @staticmethod
    def parse_header(data: bytes) -> Tuple[bytes, int, int, int, bytes]:
        if len(data) < HEADER_STATIC_SIZE:
            raise VaultError("Vault file header too small or corrupted.")
        magic, version, kdf_id, aead_id, salt_len, n_log2, r, p = struct.unpack(HEADER_FMT, data[:HEADER_STATIC_SIZE])
        if magic != HEADER_MAGIC:
            raise VaultError("Invalid vault file (bad magic).")
        if version != VERSION:
            raise VaultError(f"Unsupported vault version: {version}")
        if kdf_id != KDF_ID_SCRYPT or aead_id != AEAD_ID_AESGCM:
            raise VaultError("Unsupported KDF/AEAD.")
        if len(data) < HEADER_STATIC_SIZE + salt_len:
            raise VaultError("Vault file header truncated (salt).")
        salt = data[HEADER_STATIC_SIZE:HEADER_STATIC_SIZE + salt_len]
        header_bytes = data[:HEADER_STATIC_SIZE + salt_len]
        return header_bytes, n_log2, r, p, salt

    def exists(self) -> bool:
        return self.path.exists()

    def create_new(self, master_password: str) -> None:
        self.salt = os.urandom(SALT_LEN)
        self.kdf_params = (DEFAULT_SCRYPT_N_LOG2, DEFAULT_SCRYPT_R, DEFAULT_SCRYPT_P)
        self.header_bytes = self.build_header(self.salt, self.kdf_params)
        self.data = VaultData()
        self._save_with_key(self._derive_key(master_password))

    def unlock(self, master_password: str) -> None:
        raw = self.path.read_bytes()
        header_bytes, n_log2, r, p, salt = self.parse_header(raw)
        self.header_bytes = header_bytes
        self.kdf_params = (n_log2, r, p)
        self.salt = salt
        body = raw[len(header_bytes):]
        if len(body) < NONCE_LEN + 16:
            raise VaultError("Vault file is too short.")
        nonce = body[:NONCE_LEN]
        ciphertext = body[NONCE_LEN:]
        key = self._derive_key(master_password)
        aead = AESGCM(key)
        try:
            plaintext = aead.decrypt(nonce, ciphertext, header_bytes)
        except Exception as e:
            raise VaultError("Wrong master password or file is corrupted.") from e
        self.data = VaultData(**json.loads(plaintext.decode("utf-8")))

    def save(self, master_password: str) -> None:
        if not self.header_bytes or not self.salt:
            raise VaultError("Vault not initialized.")
        self.data.modified = time.time()
        self._save_with_key(self._derive_key(master_password))

    def _derive_key(self, master_password: str) -> bytes:
        if not self.salt:
            raise VaultError("Missing salt.")
        n_log2, r, p = self.kdf_params
        return self.derive_key_scrypt(master_password, self.salt, n_log2, r, p)

    def _save_with_key(self, key: bytes) -> None:
        if not self.header_bytes:
            raise VaultError("Missing header.")
        aead = AESGCM(key)
        nonce = secrets.token_bytes(NONCE_LEN)
        payload = json.dumps(self.data.__dict__).encode("utf-8")
        ciphertext = aead.encrypt(nonce, payload, self.header_bytes)
        blob = self.header_bytes + nonce + ciphertext
        self._atomic_write(self.path, blob)

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        path = Path(path)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        fd = os.open(str(tmp_path), flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(str(tmp_path), str(path))
        finally:
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except Exception:
                pass

    def list_services(self) -> List[str]:
        return sorted(self.data.entries.keys(), key=str.lower)

    def get_entry(self, service: str) -> Optional[Dict[str, str]]:
        return self.data.entries.get(service)

    def set_entry(self, service: str, username: str, password: str) -> None:
        self.data.entries[service] = {"username": username, "password": password, "updated": time.time()}

    def delete_entry(self, service: str) -> None:
        self.data.entries.pop(service, None)


# ------------------------- GUI -------------------------

AUTO_LOCK_SECONDS = 180
CLIPBOARD_CLEAR_MS = 20000

class PasswordDialog(simpledialog.Dialog):
    def __init__(self, parent, title, confirm=False, prompt="Enter master password"):
        self.confirm = confirm
        self.prompt = prompt
        self.password = None
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text=self.prompt).grid(row=0, column=0, columnspan=2, sticky="w", padx=4, pady=4)
        self.var1 = tk.StringVar()
        self.var2 = tk.StringVar()
        self.e1 = ttk.Entry(master, textvariable=self.var1, show="*")
        self.e1.grid(row=1, column=0, columnspan=2, sticky="ew", padx=4, pady=4)
        if self.confirm:
            ttk.Label(master, text="Confirm:").grid(row=2, column=0, sticky="w", padx=4)
            self.e2 = ttk.Entry(master, textvariable=self.var2, show="*")
            self.e2.grid(row=2, column=1, sticky="ew", padx=4, pady=4)
        master.columnconfigure(1, weight=1)
        return self.e1

    def validate(self):
        pw1 = self.var1.get()
        if not pw1:
            messagebox.showerror("Error", "Password cannot be empty")
            return False
        if self.confirm:
            pw2 = self.var2.get()
            if pw1 != pw2:
                messagebox.showerror("Error", "Passwords do not match")
                return False
        self.password = pw1
        return True


class App(tk.Tk):
    def __init__(self, vault_path: Path):
        super().__init__()
        self.title("Password Vault")
        self.geometry("700x420")
        self.minsize(640, 380)

        self.vault = Vault(vault_path)
        self.master_password: Optional[str] = None

        self.last_activity_ts = time.time()
        self.clipboard_clear_job = None
        self.locked_overlay = None

        self._build_ui()
        self._bind_activity()
        self.after(1000, self._idle_check)

        self._startup_flow()

    # ----- UI build -----
    def _build_ui(self):
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # Left frame
        left = ttk.Frame(self)
        left.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        left.rowconfigure(1, weight=1)
        ttk.Label(left, text="Services").grid(row=0, column=0, sticky="w")
        self.services_list = tk.Listbox(left, height=18)
        self.services_list.grid(row=1, column=0, sticky="nsew")
        self.services_list.bind("<<ListboxSelect>>", self._on_select_service)
        btns_left = ttk.Frame(left)
        btns_left.grid(row=2, column=0, sticky="ew", pady=(6, 0))
        ttk.Button(btns_left, text="Delete", command=self.delete_entry).pack(side="left")
        ttk.Button(btns_left, text="Refresh", command=self.refresh_services).pack(side="left", padx=(6, 0))

        # Right frame
        right = ttk.Frame(self)
        right.grid(row=0, column=1, sticky="nsew", padx=8, pady=8)
        for i in range(2):
            right.columnconfigure(i, weight=1)

        ttk.Label(right, text="Service").grid(row=0, column=0, sticky="w")
        self.var_service = tk.StringVar()
        self.entry_service = ttk.Entry(right, textvariable=self.var_service)
        self.entry_service.grid(row=0, column=1, sticky="ew", pady=2)

        ttk.Label(right, text="Username").grid(row=1, column=0, sticky="w")
        self.var_username = tk.StringVar()
        self.entry_username = ttk.Entry(right, textvariable=self.var_username)
        self.entry_username.grid(row=1, column=1, sticky="ew", pady=2)

        ttk.Label(right, text="Password").grid(row=2, column=0, sticky="w")
        self.var_password = tk.StringVar()
        self.entry_password = ttk.Entry(right, textvariable=self.var_password, show="•")
        self.entry_password.grid(row=2, column=1, sticky="ew", pady=2)

        buttons = ttk.Frame(right)
        buttons.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Button(buttons, text="Generate", command=self.generate_password).pack(side="left")
        ttk.Button(buttons, text="Reveal", command=self.toggle_reveal).pack(side="left", padx=(6, 0))
        ttk.Button(buttons, text="Copy", command=self.copy_password).pack(side="left", padx=(6, 0))
        ttk.Button(buttons, text="Save Entry", command=self.save_entry).pack(side="left", padx=(6, 0))
        ttk.Button(buttons, text="Load Entry", command=self.load_entry).pack(side="left", padx=(6, 0))

        ttk.Separator(right, orient="horizontal").grid(row=4, column=0, columnspan=2, sticky="ew", pady=8)

        bottom = ttk.Frame(right)
        bottom.grid(row=5, column=0, columnspan=2, sticky="ew")
        ttk.Button(bottom, text="Lock", command=self.lock).pack(side="left")
        ttk.Button(bottom, text="Save Vault", command=self.save_vault).pack(side="left", padx=(6, 0))
        ttk.Label(bottom, text=f"Idle auto-lock: {AUTO_LOCK_SECONDS}s").pack(side="right")

    # ----- Activity and idle -----
    def _bind_activity(self):
        def touch(_=None):
            self.last_activity_ts = time.time()
        for seq in ("<Key>", "<Button>", "<Motion>", "<<ListboxSelect>>"):
            self.bind_all(seq, touch)

    def _startup_flow(self):
        try:
            if self.vault.exists():
                while True:
                    dlg = PasswordDialog(self, "Unlock Vault")
                    if dlg.password is None:
                        self.quit()
                        return
                    try:
                        self.vault.unlock(dlg.password)
                        self.master_password = dlg.password
                        break
                    except VaultError as e:
                        messagebox.showerror("Unlock failed", str(e))
                        continue
            else:
                dlg = PasswordDialog(self, "Create Vault", confirm=True, prompt="Create a master password")
                if dlg.password is None:
                    self.quit()
                    return
                self.vault.create_new(dlg.password)
                self.master_password = dlg.password
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open vault: {e}")
            self.quit()
            return
        self.refresh_services()

    def _idle_check(self):
        if self.master_password is not None:
            idle = time.time() - self.last_activity_ts
            if idle >= AUTO_LOCK_SECONDS:
                self.lock()
        self.after(1000, self._idle_check)

    # ----- Lock / Unlock -----
    def lock(self):
        if self.master_password is None:
            return
        self.master_password = None
        self.vault.data = VaultData()
        if self.locked_overlay:
            return
        self.locked_overlay = tk.Toplevel(self)
        self.locked_overlay.title("Locked")
        self.locked_overlay.transient(self)
        self.locked_overlay.grab_set()
        self.locked_overlay.geometry("300x120+{}+{}".format(self.winfo_rootx() + 50, self.winfo_rooty() + 50))
        self.locked_overlay.protocol("WM_DELETE_WINDOW", lambda: None)
        ttk.Label(self.locked_overlay, text="Vault is locked").pack(pady=10)
        btn = ttk.Button(self.locked_overlay, text="Unlock", command=self._unlock_from_overlay)
        btn.pack()
        btn.focus_set()

    def _unlock_from_overlay(self):
        dlg = PasswordDialog(self.locked_overlay, "Unlock Vault")
        if dlg.password is None:
            return
        try:
            self.vault.unlock(dlg.password)
            self.master_password = dlg.password
            self.locked_overlay.destroy()
            self.locked_overlay = None
            self.refresh_services()
            messagebox.showinfo("Unlocked", "Vault unlocked.")
        except VaultError as e:
            messagebox.showerror("Unlock failed", str(e))

    # ----- Entry operations -----
    def refresh_services(self):
        self.services_list.delete(0, tk.END)
        for svc in self.vault.list_services():
            self.services_list.insert(tk.END, svc)

    def _on_select_service(self, event=None):
        sel = self.services_list.curselection()
        if not sel:
            return
        svc = self.services_list.get(sel[0])
        self.var_service.set(svc)
        entry = self.vault.get_entry(svc)
        if entry:
            self.var_username.set(entry.get("username", ""))
            self.var_password.set(entry.get("password", ""))

    def save_entry(self):
        if not self._ensure_unlocked():
            return
        svc = self.var_service.get().strip()
        if not svc:
            messagebox.showerror("Error", "Service name is required.")
            return
        username = self.var_username.get()
        password = self.var_password.get()
        self.vault.set_entry(svc, username, password)
        try:
            self.vault.save(self.master_password)
            self.refresh_services()
            messagebox.showinfo("Saved", f"Entry saved for '{svc}'.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}")

    def load_entry(self):
        svc = self.var_service.get().strip()
        if not svc:
            messagebox.showerror("Error", "Enter a service name or select one.")
            return
        entry = self.vault.get_entry(svc)
        if not entry:
            messagebox.showinfo("Not found", f"No entry for '{svc}'.")
            return
        self.var_username.set(entry.get("username", ""))
        self.var_password.set(entry.get("password", ""))

    def delete_entry(self):
        if not self._ensure_unlocked():
            return
        sel = self.services_list.curselection()
        if not sel:
            svc = self.var_service.get().strip()
        else:
            svc = self.services_list.get(sel[0])
        if not svc:
            messagebox.showerror("Error", "Select or enter a service to delete.")
            return
        if not messagebox.askyesno("Confirm", f"Delete entry '{svc}'? This cannot be undone."):
            return
        self.vault.delete_entry(svc)
        try:
            self.vault.save(self.master_password)
            self.refresh_services()
            self.var_service.set("")
            self.var_username.set("")
            self.var_password.set("")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}")

    # ----- Helpers -----
    def generate_password(self):
        length = 20
        alphabet = (
            "ABCDEFGHJKLMNPQRSTUVWXYZ"
            "abcdefghijkmnopqrstuvwxyz"
            "23456789"
            "!@#$%^&*()-_=+[]{};:,.?"
        )
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        self.var_password.set(pwd)

    def toggle_reveal(self):
        if self.entry_password.cget("show") == "":
            self.entry_password.config(show="•")
        else:
            self.entry_password.config(show="")

    def copy_password(self):
        pwd = self.var_password.get()
        if not pwd:
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(pwd)
            self.update()
            if self.clipboard_clear_job:
                self.after_cancel(self.clipboard_clear_job)
            self.clipboard_clear_job = self.after(CLIPBOARD_CLEAR_MS, self._clear_clipboard_safe)
            messagebox.showinfo("Copied", "Password copied to clipboard (will clear automatically).")
        except Exception as e:
            messagebox.showerror("Clipboard", f"Failed to copy: {e}")

    def _clear_clipboard_safe(self):
        try:
            self.clipboard_clear()
            self.update()
        except Exception:
            pass
        self.clipboard_clear_job = None

    def save_vault(self):
        if not self._ensure_unlocked():
            return
        try:
            self.vault.save(self.master_password)
            messagebox.showinfo("Saved", "Vault saved.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}")

    def _ensure_unlocked(self) -> bool:
        if self.master_password is None:
            messagebox.showwarning("Locked", "Vault is locked. Click Unlock to continue.")
            return False
        return True

# ------------------------- Main -------------------------

def main():
    if getattr(sys, "frozen", False):
        base_dir = Path(os.path.dirname(sys.executable))
    else:
        base_dir = Path.cwd()
    vault_path = base_dir / "vault.dat"
    app = App(vault_path)
    app.mainloop()

if __name__ == "__main__":
    main()
