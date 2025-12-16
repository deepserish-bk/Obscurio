#!/usr/bin/env python3
"""
Obscurio - Secure Password Manager with GUI
AES-GCM encrypted password vault with Scrypt key derivation.
"""

import json
import base64
import os
import sys
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import secrets

# Core cryptography imports
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidTag
    CRYPTO_AVAILABLE = True
except ImportError:
    print("ERROR: Required cryptography library not found.")
    print("Install with: pip install cryptography")
    sys.exit(1)

# GUI imports - using Tkinter (built-in)
try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    import tkinter.scrolledtext as scrolledtext
    GUI_AVAILABLE = True
except ImportError:
    print("ERROR: Tkinter not available. GUI cannot be loaded.")
    GUI_AVAILABLE = False

@dataclass
class Credential:
    """Encrypted credential entry."""
    service: str
    encrypted_username: str
    encrypted_password: str
    url: str = ""
    notes: str = ""
    created: str = ""
    updated: str = ""
    nonce: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Credential':
        return cls(**data)

class EncryptionManager:
    """Handles all cryptographic operations."""
    
    def __init__(self):
        self.scrypt_n = 2**14
        self.scrypt_r = 8
        self.scrypt_p = 1
        self.salt_size = 16
        self.nonce_size = 12
    
    def generate_salt(self) -> bytes:
        return secrets.token_bytes(self.salt_size)
    
    def generate_nonce(self) -> bytes:
        return secrets.token_bytes(self.nonce_size)
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=self.scrypt_n,
            r=self.scrypt_r,
            p=self.scrypt_p,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def encrypt_data(self, key: bytes, plaintext: str) -> tuple[str, str]:
        nonce = self.generate_nonce()
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        return base64.b64encode(ciphertext).decode('utf-8'), \
               base64.b64encode(nonce).decode('utf-8')
    
    def decrypt_data(self, key: bytes, encrypted_data: str, nonce_b64: str) -> str:
        try:
            aesgcm = AESGCM(key)
            ciphertext = base64.b64decode(encrypted_data)
            nonce = base64.b64decode(nonce_b64)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except InvalidTag:
            raise ValueError("Decryption failed - invalid tag")
        except Exception as e:
            raise ValueError(f"Decryption error: {str(e)}")

class Vault:
    """Main vault management class."""
    
    def __init__(self, vault_path: str = "obscurio_vault.json"):
        self.vault_path = vault_path
        self.credentials: Dict[str, Credential] = {}
        self.encryption_manager = EncryptionManager()
        self.master_key: Optional[bytes] = None
        self.salt: Optional[bytes] = None
        self.is_locked = True
        self.auto_lock_minutes = 5
        self.lock_timer: Optional[threading.Timer] = None
        
        self.version = "1.0"
        self.created = datetime.now().isoformat()
        self.modified = self.created
    
    def _reset_lock_timer(self):
        """Reset the auto-lock timer."""
        if self.lock_timer:
            self.lock_timer.cancel()
        
        if not self.is_locked and self.auto_lock_minutes > 0:
            self.lock_timer = threading.Timer(
                self.auto_lock_minutes * 60,
                self._auto_lock
            )
            self.lock_timer.daemon = True
            self.lock_timer.start()
    
    def _auto_lock(self):
        """Auto-lock the vault."""
        if not self.is_locked:
            self.lock()
            if GUI_AVAILABLE and hasattr(self, 'gui'):
                self.gui.on_vault_locked()
    
    def create_vault(self, password: str) -> bool:
        if os.path.exists(self.vault_path):
            return False
        
        self.salt = self.encryption_manager.generate_salt()
        self.master_key = self.encryption_manager.derive_key(password, self.salt)
        self.is_locked = False
        self._reset_lock_timer()
        return True
    
    def unlock_vault(self, password: str) -> bool:
        if not os.path.exists(self.vault_path):
            return False
        
        try:
            with open(self.vault_path, 'r') as f:
                vault_data = json.load(f)
            
            salt_b64 = vault_data['salt']
            self.salt = base64.b64decode(salt_b64)
            self.master_key = self.encryption_manager.derive_key(password, self.salt)
            
            # LOAD CREDENTIALS FROM FILE - FIXED
            self.credentials.clear()
            for cred_data in vault_data.get('credentials', []):
                cred = Credential.from_dict(cred_data)
                self.credentials[cred.service] = cred
            
            # Verify by trying to decrypt first credential if exists
            if self.credentials:
                cred = list(self.credentials.values())[0]
                try:
                    self.encryption_manager.decrypt_data(
                        self.master_key, 
                        cred.encrypted_username, 
                        cred.nonce
                    )
                except ValueError:
                    # Decryption failed - wrong password
                    self.credentials.clear()
                    self.master_key = None
                    self.is_locked = True
                    return False
            
            self.is_locked = False
            self._reset_lock_timer()
            return True
            
        except Exception as e:
            print(f"Unlock failed: {str(e)}")
            self.master_key = None
            self.is_locked = True
            return False
    
    def add_credential(self, service: str, username: str, password: str, **kwargs):
        if self.is_locked:
            raise RuntimeError("Vault is locked")
        
        if not self.master_key:
            raise RuntimeError("Master key not available")
        
        enc_username, nonce_user = self.encryption_manager.encrypt_data(
            self.master_key, username
        )
        enc_password, _ = self.encryption_manager.encrypt_data(
            self.master_key, password
        )
        
        cred = Credential(
            service=service,
            encrypted_username=enc_username,
            encrypted_password=enc_password,
            nonce=nonce_user,
            created=datetime.now().isoformat(),
            updated=datetime.now().isoformat(),
            **kwargs
        )
        
        self.credentials[service] = cred
        self.modified = datetime.now().isoformat()
        self._reset_lock_timer()
    
    def get_credential(self, service: str) -> Optional[tuple[str, str]]:
        if self.is_locked:
            return None
        
        if service not in self.credentials:
            return None
        
        self._reset_lock_timer()
        cred = self.credentials[service]
        
        try:
            username = self.encryption_manager.decrypt_data(
                self.master_key, cred.encrypted_username, cred.nonce
            )
            password = self.encryption_manager.decrypt_data(
                self.master_key, cred.encrypted_password, cred.nonce
            )
            return username, password
        except ValueError as e:
            print(f"Decryption failed: {str(e)}")
            return None
    
    def save_vault(self):
        if self.is_locked:
            raise RuntimeError("Cannot save locked vault")
        
        vault_data = {
            'version': self.version,
            'created': self.created,
            'modified': self.modified,
            'salt': base64.b64encode(self.salt).decode('utf-8') if self.salt else '',
            'credentials': [cred.to_dict() for cred in self.credentials.values()]
        }
        
        with open(self.vault_path, 'w') as f:
            json.dump(vault_data, f, indent=2)
        
        self._reset_lock_timer()
    
    def lock(self):
        if self.lock_timer:
            self.lock_timer.cancel()
        
        if self.master_key:
            self.master_key = b'\x00' * len(self.master_key)
            self.master_key = None
        
        self.is_locked = True

class ObscurioGUI:
    """Main GUI application."""
    
    def __init__(self):
        self.vault = Vault()
        self.vault.gui = self  # Allow vault to call GUI methods
        
        if not GUI_AVAILABLE:
            messagebox.showerror("Error", "Tkinter not available. Cannot start GUI.")
            sys.exit(1)
        
        self.root = tk.Tk()
        self.root.title("Obscurio - Secure Password Manager")
        self.root.geometry("800x600")
        
        # Configure styles
        self.setup_styles()
        
        # Start with login screen
        self.show_login_screen()
    
    def setup_styles(self):
        """Configure GUI styles."""
        style = ttk.Style()
        style.configure("Title.TLabel", font=("Arial", 16, "bold"))
        style.configure("Heading.TLabel", font=("Arial", 12, "bold"))
        style.configure("Success.TLabel", foreground="green")
        style.configure("Error.TLabel", foreground="red")
    
    def clear_window(self):
        """Clear all widgets from window."""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def show_login_screen(self):
        """Show login/create vault screen."""
        self.clear_window()
        
        # Title
        title = ttk.Label(self.root, text="🔐 Obscurio Password Manager", 
                         style="Title.TLabel")
        title.pack(pady=20)
        
        # Frame for options
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill="both", expand=True)
        
        # Check if vault exists
        vault_exists = os.path.exists(self.vault.vault_path)
        
        if vault_exists:
            # Login to existing vault
            ttk.Label(frame, text="Unlock Existing Vault", 
                     style="Heading.TLabel").pack(pady=10)
            
            ttk.Label(frame, text="Master Password:").pack(pady=5)
            self.password_entry = ttk.Entry(frame, show="•", width=30)
            self.password_entry.pack(pady=5)
            self.password_entry.focus_set()  # Fixed focus
            
            # Bind Enter key to unlock
            self.password_entry.bind('<Return>', lambda e: self.unlock_vault())
            
            ttk.Button(frame, text="Unlock Vault", 
                      command=self.unlock_vault).pack(pady=10)
            
            ttk.Button(frame, text="Create New Vault", 
                      command=self.show_create_vault_screen).pack(pady=5)
        
        else:
            # Create new vault
            self.show_create_vault_screen()
    
    def show_create_vault_screen(self):
        """Show screen for creating new vault."""
        self.clear_window()
        
        title = ttk.Label(self.root, text="Create New Vault", 
                         style="Title.TLabel")
        title.pack(pady=20)
        
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill="both", expand=True)
        
        # Password fields
        ttk.Label(frame, text="Master Password (min 12 chars):").pack(pady=5)
        self.new_password_entry = ttk.Entry(frame, show="•", width=30)
        self.new_password_entry.pack(pady=5)
        self.new_password_entry.focus_set()
        
        ttk.Label(frame, text="Confirm Password:").pack(pady=5)
        self.confirm_password_entry = ttk.Entry(frame, show="•", width=30)
        self.confirm_password_entry.pack(pady=5)
        
        # Bind Enter to create vault
        self.confirm_password_entry.bind('<Return>', lambda e: self.create_vault())
        
        # Warning label
        warning = ttk.Label(frame, 
            text="⚠️ IMPORTANT: If you lose this password, your data cannot be recovered.",
            foreground="orange", wraplength=400)
        warning.pack(pady=10)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="Create Vault", 
                  command=self.create_vault).pack(side="left", padx=5)
        
        if os.path.exists(self.vault.vault_path):
            ttk.Button(button_frame, text="Back to Login", 
                      command=self.show_login_screen).pack(side="left", padx=5)
    
    def unlock_vault(self):
        """Attempt to unlock vault with entered password."""
        password = self.password_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        # Show loading
        self.root.config(cursor="wait")
        self.root.update()
        
        try:
            if self.vault.unlock_vault(password):
                self.show_main_screen()
            else:
                messagebox.showerror("Error", "Incorrect password or corrupted vault")
        finally:
            self.root.config(cursor="")
    
    def create_vault(self):
        """Create new vault with entered password."""
        password = self.new_password_entry.get()
        confirm = self.confirm_password_entry.get()
        
        if len(password) < 12:
            messagebox.showwarning("Weak Password", 
                "Password should be at least 12 characters for security.")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if not self.vault.create_vault(password):
            messagebox.showerror("Error", "Vault already exists or creation failed")
            return
        
        messagebox.showinfo("Success", "Vault created successfully!")
        self.show_main_screen()
    
    def show_main_screen(self):
        """Show main application screen with credentials."""
        self.clear_window()
        
        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Vault", command=self.save_vault)
        file_menu.add_separator()
        file_menu.add_command(label="Lock Vault", command=self.lock_vault)
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Title
        title_frame = ttk.Frame(self.root)
        title_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(title_frame, text="Obscurio Password Manager", 
                 style="Title.TLabel").pack(side="left")
        
        # Status indicator
        self.status_label = ttk.Label(title_frame, text="🔓 Unlocked", 
                                     foreground="green")
        self.status_label.pack(side="right")
        
        # Main content frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Left panel - Credentials list
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side="left", fill="y", padx=(0, 10))
        
        ttk.Label(left_frame, text="Stored Credentials", 
                 style="Heading.TLabel").pack(pady=5)
        
        # Listbox for credentials
        list_frame = ttk.Frame(left_frame)
        list_frame.pack(fill="both", expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.cred_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set,
                                      selectmode="single", height=15)
        self.cred_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.cred_listbox.yview)
        
        # Bind selection event
        self.cred_listbox.bind('<<ListboxSelect>>', self.on_credential_select)
        
        # Refresh list - FIXED: Call this to show credentials
        
        # Buttons for left panel
        button_frame = ttk.Frame(left_frame)
        button_frame.pack(fill="x", pady=10)
        
        ttk.Button(button_frame, text="Add New", 
                  command=self.show_add_credential_dialog).pack(side="left", padx=2)
        ttk.Button(button_frame, text="Refresh", 
                  command=self.refresh_credential_list).pack(side="left", padx=2)
        ttk.Button(button_frame, text="Delete", 
                  command=self.delete_selected_credential).pack(side="left", padx=2)
        
        # Right panel - Credential details
        right_frame = ttk.LabelFrame(main_frame, text="Credential Details", padding=10)
        right_frame.pack(side="right", fill="both", expand=True)
        
        # Credential details labels
        detail_labels = ["Service:", "Username:", "Password:", "URL:", "Notes:"]
        self.detail_vars = {}
        
        for i, label in enumerate(detail_labels):
            ttk.Label(right_frame, text=label).grid(row=i, column=0, sticky="w", pady=5)
            var = tk.StringVar()
            entry = ttk.Entry(right_frame, textvariable=var, state="readonly", width=40)
            entry.grid(row=i, column=1, sticky="ew", pady=5, padx=(5, 0))
            self.detail_vars[label[:-1].lower()] = var
        
        # Copy buttons
        button_frame2 = ttk.Frame(right_frame)
        button_frame2.grid(row=len(detail_labels), column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame2, text="Copy Username", 
                  command=lambda: self.copy_to_clipboard("username")).pack(side="left", padx=2)
        ttk.Button(button_frame2, text="Copy Password", 
                  command=lambda: self.copy_to_clipboard("password")).pack(side="left", padx=2)
        
        # Bottom status bar
        # Refresh credential list
        self.refresh_credential_list()

        status_frame = ttk.Frame(self.root, relief="sunken", borderwidth=1)
        status_frame.pack(side="bottom", fill="x")
        
        self.status_text = tk.StringVar(value=f"Loaded {len(self.vault.credentials)} credentials")
        ttk.Label(status_frame, textvariable=self.status_text).pack(side="left", padx=5)
        
        # Auto-lock warning
        if self.vault.auto_lock_minutes > 0:
            lock_text = f"Auto-lock in {self.vault.auto_lock_minutes} min"
            ttk.Label(status_frame, text=lock_text).pack(side="right", padx=5)
    
    def refresh_credential_list(self):
        """Refresh the list of credentials."""
        self.cred_listbox.delete(0, tk.END)
        
        if not self.vault.credentials:
            self.status_text.set("No credentials found. Click 'Add New' to create one.")
        else:
            for service in sorted(self.vault.credentials.keys()):
                self.cred_listbox.insert(tk.END, service)
            self.status_text.set(f"Found {len(self.vault.credentials)} credentials")
    
    def on_credential_select(self, event):
        """Handle credential selection from list."""
        selection = self.cred_listbox.curselection()
        if not selection:
            return
        
        service = self.cred_listbox.get(selection[0])
        cred_info = self.vault.get_credential(service)
        
        if cred_info:
            username, password = cred_info
            cred = self.vault.credentials[service]
            
            self.detail_vars["service"].set(service)
            self.detail_vars["username"].set(username)
            self.detail_vars["password"].set("••••••••")
            self.detail_vars["url"].set(cred.url)
            self.detail_vars["notes"].set(cred.notes)
    
    def show_add_credential_dialog(self):
        """Show dialog to add new credential."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Credential")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Form fields
        fields = [
            ("Service:", "service"),
            ("Username/Email:", "username"),
            ("Password:", "password", True),
            ("URL (optional):", "url"),
            ("Notes (optional):", "notes")
        ]
        
        entries = {}
        
        for i, (label, key, *options) in enumerate(fields):
            ttk.Label(dialog, text=label).grid(row=i, column=0, sticky="w", padx=10, pady=5)
            
            if options and options[0]:  # Show password as bullets
                entry = ttk.Entry(dialog, show="•", width=30)
            else:
                entry = ttk.Entry(dialog, width=30)
            
            entry.grid(row=i, column=1, padx=10, pady=5, sticky="ew")
            entries[key] = entry
        
        # Focus on service field
        entries["service"].focus_set()
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=len(fields), column=0, columnspan=2, pady=20)
        
        def save_credential():
            service = entries["service"].get().strip()
            username = entries["username"].get().strip()
            password = entries["password"].get().strip()
            
            if not service:
                messagebox.showerror("Error", "Service name is required")
                return
            if not username:
                messagebox.showerror("Error", "Username is required")
                return
            if not password:
                messagebox.showerror("Error", "Password is required")
                return
            
            try:
                self.vault.add_credential(
                    service=service,
                    username=username,
                    password=password,
                    url=entries["url"].get().strip(),
                    notes=entries["notes"].get().strip()
                )
                # SAVE TO FILE - FIXED
                self.vault.save_vault()
                self.refresh_credential_list()
                dialog.destroy()
                messagebox.showinfo("Success", "Credential added successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add credential: {str(e)}")
        
        ttk.Button(button_frame, text="Save", 
                  command=save_credential).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancel", 
                  command=dialog.destroy).pack(side="left", padx=5)
        
        # Bind Enter to save
        entries["notes"].bind('<Return>', lambda e: save_credential())
    
    def delete_selected_credential(self):
        """Delete selected credential."""
        selection = self.cred_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a credential to delete")
            return
        
        service = self.cred_listbox.get(selection[0])
        
        if messagebox.askyesno("Confirm Delete", 
                              f"Delete credential for '{service}'?"):
            del self.vault.credentials[service]
            # Save after deletion
            try:
                self.vault.save_vault()
            except:
                pass
            self.refresh_credential_list()
            # Clear detail fields
            for var in self.detail_vars.values():
                var.set("")
            messagebox.showinfo("Deleted", f"Credential for '{service}' deleted")
    
    def copy_to_clipboard(self, field_type):
        """Copy username or password to clipboard."""
        selection = self.cred_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a credential first")
            return
        
        service = self.cred_listbox.get(selection[0])
        cred_info = self.vault.get_credential(service)
        
        if not cred_info:
            messagebox.showerror("Error", "Could not retrieve credential")
            return
        
        username, password = cred_info
        text_to_copy = username if field_type == "username" else password
        
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text_to_copy)
            self.status_text.set(f"Copied {field_type} to clipboard")
            
            # Auto-clear clipboard after 30 seconds
            def clear_clipboard():
                self.root.clipboard_clear()
                self.status_text.set("Clipboard cleared for security")
            
            self.root.after(30000, clear_clipboard)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy to clipboard: {str(e)}")
    
    def save_vault(self):
        """Save vault to disk."""
        try:
            self.vault.save_vault()
            self.status_text.set("Vault saved successfully")
            messagebox.showinfo("Success", "Vault saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save vault: {str(e)}")
    
    def lock_vault(self):
        """Lock the vault and return to login screen."""
        save = messagebox.askyesno("Lock Vault", "Save vault before locking?")
        if save:
            try:
                self.vault.save_vault()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {str(e)}")
        
        self.vault.lock()
        self.show_login_screen()
    
    def on_vault_locked(self):
        """Called when vault auto-locks."""
        if messagebox.askyesno("Auto-Locked", 
                              "Vault has been auto-locked due to inactivity.\n\nReturn to login screen?"):
            self.root.after(100, self.lock_vault)
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()

if __name__ == "__main__":
    """Main entry point."""
    if GUI_AVAILABLE:
        app = ObscurioGUI()
        app.run()
    else:
        print("GUI not available.")
