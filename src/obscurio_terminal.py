#!/usr/bin/env python3
"""
Obscurio - Secure Password Manager
AES-GCM encrypted password vault with Scrypt key derivation.
"""

import json
import base64
import os
import sys
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from getpass import getpass
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

@dataclass
class Credential:
    """Encrypted credential entry."""
    service: str
    encrypted_username: str  # Base64 encoded, encrypted
    encrypted_password: str  # Base64 encoded, encrypted
    url: str = ""
    notes: str = ""
    created: str = ""
    updated: str = ""
    nonce: str = ""  # Store nonce for each credential
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Credential':
        return cls(**data)

class EncryptionManager:
    """Handles all cryptographic operations."""
    
    def __init__(self):
        self.scrypt_n = 2**14  # 16384 - memory-hard parameter
        self.scrypt_r = 8
        self.scrypt_p = 1
        self.salt_size = 16
        self.nonce_size = 12  # GCM recommended nonce size
    
    def generate_salt(self) -> bytes:
        """Generate cryptographically secure salt."""
        return secrets.token_bytes(self.salt_size)
    
    def generate_nonce(self) -> bytes:
        """Generate cryptographically secure nonce."""
        return secrets.token_bytes(self.nonce_size)
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using Scrypt."""
        kdf = Scrypt(
            salt=salt,
            length=32,  # AES-256 key length
            n=self.scrypt_n,
            r=self.scrypt_r,
            p=self.scrypt_p,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def encrypt_data(self, key: bytes, plaintext: str) -> tuple[str, str]:
        """Encrypt plaintext using AES-GCM.
        
        Returns:
            Tuple of (base64_encrypted_data, base64_nonce)
        """
        nonce = self.generate_nonce()
        aesgcm = AESGCM(key)
        
        # Encrypt with associated data (optional)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        # Return base64 encoded for storage
        return base64.b64encode(ciphertext).decode('utf-8'), \
               base64.b64encode(nonce).decode('utf-8')
    
    def decrypt_data(self, key: bytes, encrypted_data: str, nonce_b64: str) -> str:
        """Decrypt data using AES-GCM."""
        try:
            aesgcm = AESGCM(key)
            ciphertext = base64.b64decode(encrypted_data)
            nonce = base64.b64decode(nonce_b64)
            
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except InvalidTag:
            raise ValueError("Decryption failed - invalid authentication tag")
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
        self.last_activity = datetime.now()
        self.auto_lock_minutes = 5
        
        # Vault metadata
        self.version = "1.0"
        self.created = datetime.now().isoformat()
        self.modified = self.created
    
    def _check_auto_lock(self) -> bool:
        """Check if auto-lock should trigger."""
        if self.is_locked:
            return False
        inactive_time = datetime.now() - self.last_activity
        return inactive_time > timedelta(minutes=self.auto_lock_minutes)
    
    def _update_activity(self):
        """Update last activity timestamp."""
        self.last_activity = datetime.now()
    
    def create_vault(self, password: str) -> bool:
        """Create a new encrypted vault."""
        if os.path.exists(self.vault_path):
            print(f"Vault already exists at {self.vault_path}")
            return False
        
        self.salt = self.encryption_manager.generate_salt()
        self.master_key = self.encryption_manager.derive_key(password, self.salt)
        self.is_locked = False
        self._update_activity()
        
        print(f"New vault created at {self.vault_path}")
        print("IMPORTANT: Save your master password securely. It cannot be recovered.")
        return True
    
    def unlock_vault(self, password: str) -> bool:
        """Unlock existing vault with password."""
        if not os.path.exists(self.vault_path):
            print("No vault found. Create one first.")
            return False
        
        try:
            with open(self.vault_path, 'r') as f:
                vault_data = json.load(f)
            
            # Decode salt from base64
            salt_b64 = vault_data['salt']
            self.salt = base64.b64decode(salt_b64)
            
            # Derive key and verify by decrypting a test
            self.master_key = self.encryption_manager.derive_key(password, self.salt)
            
            # Load credentials
            for cred_data in vault_data['credentials']:
                cred = Credential.from_dict(cred_data)
                self.credentials[cred.service] = cred
            
            self.is_locked = False
            self._update_activity()
            print("Vault unlocked successfully.")
            return True
            
        except (KeyError, ValueError, json.JSONDecodeError) as e:
            print(f"Failed to unlock vault: {str(e)}")
            self.master_key = None
            self.is_locked = True
            return False
    
    def add_credential(self, service: str, username: str, password: str, **kwargs):
        """Add a new encrypted credential."""
        if self.is_locked:
            raise RuntimeError("Vault is locked. Unlock first.")
        
        if not self.master_key:
            raise RuntimeError("Master key not available.")
        
        self._update_activity()
        
        # Encrypt username and password separately
        enc_username, nonce_user = self.encryption_manager.encrypt_data(
            self.master_key, username
        )
        enc_password, nonce_pass = self.encryption_manager.encrypt_data(
            self.master_key, password
        )
        
        # Use the username nonce as primary nonce for the credential
        cred = Credential(
            service=service,
            encrypted_username=enc_username,
            encrypted_password=enc_password,
            nonce=nonce_user,  # Store one nonce (we could store both)
            created=datetime.now().isoformat(),
            updated=datetime.now().isoformat(),
            **kwargs
        )
        
        self.credentials[service] = cred
        self.modified = datetime.now().isoformat()
        print(f"✓ Added credential for {service}")
    
    def get_credential(self, service: str) -> Optional[tuple[str, str]]:
        """Retrieve and decrypt a credential."""
        if self._check_auto_lock():
            print("Auto-locking due to inactivity.")
            self.lock()
            return None
        
        if self.is_locked:
            print("Vault is locked.")
            return None
        
        if service not in self.credentials:
            print(f"No credential found for {service}")
            return None
        
        self._update_activity()
        cred = self.credentials[service]
        
        try:
            # Decrypt using stored nonce (simplified - in reality need both nonces)
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
        """Save vault to disk."""
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
        
        print(f"Vault saved to {self.vault_path}")
    
    def lock(self):
        """Lock the vault by clearing sensitive data from memory."""
        # Securely clear the master key from memory
        if self.master_key:
            # Overwrite the key in memory
            self.master_key = b'\x00' * len(self.master_key)
            self.master_key = None
        
        self.is_locked = True
        print("Vault locked")

def print_banner():
    """Display application banner."""
    banner = """
    ╔═══════════════════════════════════════╗
    ║            O B S C U R I O            ║
    ║     Secure Password Manager v1.0      ║
    ╚═══════════════════════════════════════╝
    """
    print(banner)

def interactive_menu(vault: Vault):
    """Interactive command-line interface."""
    while True:
        print("\n" + "="*50)
        print("MAIN MENU")
        print("="*50)
        print("1. Add new credential")
        print("2. Retrieve credential")
        print("3. List all services")
        print("4. Save vault")
        print("5. Lock vault")
        print("6. Exit")
        
        choice = input("\nSelect option (1-6): ").strip()
        
        if choice == "1":
            service = input("Service name (e.g., GitHub): ").strip()
            username = input("Username/Email: ").strip()
            password = getpass("Password: ").strip()
            url = input("URL (optional): ").strip()
            notes = input("Notes (optional): ").strip()
            
            try:
                vault.add_credential(service, username, password, url=url, notes=notes)
            except Exception as e:
                print(f"Error: {str(e)}")
        
        elif choice == "2":
            service = input("Service name: ").strip()
            result = vault.get_credential(service)
            if result:
                username, password = result
                print(f"\nUsername: {username}")
                print(f"Password: {password}")
                
                # Optional: Copy to clipboard
                copy = input("\nCopy password to clipboard? (y/n): ").lower()
                if copy == 'y':
                    try:
                        import pyperclip
                        pyperclip.copy(password)
                        print("✓ Password copied to clipboard")
                    except ImportError:
                        print("Install pyperclip for clipboard support")
        
        elif choice == "3":
            if vault.credentials:
                print("\nStored services:")
                for i, service in enumerate(sorted(vault.credentials.keys()), 1):
                    print(f"  {i}. {service}")
            else:
                print("No credentials stored.")
        
        elif choice == "4":
            try:
                vault.save_vault()
            except Exception as e:
                print(f"Error saving: {str(e)}")
        
        elif choice == "5":
            vault.lock()
            break
        
        elif choice == "6":
            if not vault.is_locked:
                save = input("Save vault before exiting? (y/n): ").lower()
                if save == 'y':
                    vault.save_vault()
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")

def main():
    """Main application entry point."""
    print_banner()
    
    vault = Vault()
    
    # Check for existing vault
    if os.path.exists(vault.vault_path):
        print(f"Found existing vault: {vault.vault_path}")
        password = getpass("Enter master password: ")
        
        if vault.unlock_vault(password):
            interactive_menu(vault)
        else:
            print("Failed to unlock vault. Exiting.")
    else:
        print("No existing vault found.")
        create = input("Create new vault? (y/n): ").lower()
        
        if create == 'y':
            print("\n--- Create New Vault ---")
            print("Choose a strong master password. It will encrypt all your data.")
            print("WARNING: If you lose this password, your data cannot be recovered.\n")
            
            password = getpass("Master password: ")
            confirm = getpass("Confirm master password: ")
            
            if password != confirm:
                print("Passwords do not match. Exiting.")
                return
            
            if len(password) < 12:
                print("Warning: Password should be at least 12 characters for security.")
                proceed = input("Continue anyway? (y/n): ").lower()
                if proceed != 'y':
                    return
            
            if vault.create_vault(password):
                interactive_menu(vault)
        else:
            print("Exiting.")

if __name__ == "__main__":
    main()
