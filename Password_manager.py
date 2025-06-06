import os
import json
import string
import secrets
import base64
import hashlib
from tkinter import *
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet, InvalidToken

PASSWORD_FILE = "passwords.enc"
SALT_FILE = "salt.bin"
MASTER_HASH_FILE = "master.hash"


def generate_salt():
    salt = secrets.token_bytes(16)
    with open(SALT_FILE, 'wb') as f:
        f.write(salt)
    return salt


def load_salt():
    if not os.path.exists(SALT_FILE):
        return generate_salt()
    with open(SALT_FILE, 'rb') as f:
        return f.read()


def derive_key(master_password, salt):
    """
    Derive a 32-byte key from the master password and salt using PBKDF2 HMAC SHA256
    """
    return hashlib.pbkdf2_hmac(
        'sha256',
        master_password.encode(),
        salt,
        100_000,
        dklen=32
    )


def get_fernet_key(master_password):
    salt = load_salt()
    key_32 = derive_key(master_password, salt)
    # Fernet expects a base64-encoded 32-byte key
    return base64.urlsafe_b64encode(key_32)


def save_master_hash(master_password):
    """
    Save a SHA256 hash of the master password (not the password itself!)
    """
    hash_pw = hashlib.sha256(master_password.encode()).hexdigest()
    with open(MASTER_HASH_FILE, 'w') as f:
        f.write(hash_pw)


def load_master_hash():
    if not os.path.exists(MASTER_HASH_FILE):
        return None
    with open(MASTER_HASH_FILE, 'r') as f:
        return f.read()


def verify_master_password(master_password):
    stored_hash = load_master_hash()
    if stored_hash is None:
        # First time setup: save hash
        save_master_hash(master_password)
        return True
    # Check if entered password hash matches stored hash
    return stored_hash == hashlib.sha256(master_password.encode()).hexdigest()


def encrypt_data(data, fernet):
    return fernet.encrypt(data.encode())


def decrypt_data(data, fernet):
    return fernet.decrypt(data).decode()


def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))


def load_passwords(fernet):
    if not os.path.exists(PASSWORD_FILE):
        return {}
    try:
        with open(PASSWORD_FILE, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = decrypt_data(encrypted_data, fernet)
        return json.loads(decrypted_data)
    except (InvalidToken, json.JSONDecodeError):
        messagebox.showerror("Error", "Failed to decrypt passwords file. Maybe wrong master password?")
        return None


def save_passwords(passwords, fernet):
    data = json.dumps(passwords)
    encrypted_data = encrypt_data(data, fernet)
    with open(PASSWORD_FILE, 'wb') as f:
        f.write(encrypted_data)


class PasswordManagerApp:
    def __init__(self, master, fernet):
        self.master = master
        self.fernet = fernet
        master.title("Password Manager")

        self.passwords = load_passwords(self.fernet)
        if self.passwords is None:
            self.passwords = {}

        # GUI Elements
        self.label_service = Label(master, text="Service:")
        self.label_service.grid(row=0, column=0, padx=10, pady=5)

        self.entry_service = Entry(master, width=30)
        self.entry_service.grid(row=0, column=1, padx=10, pady=5)

        self.label_password = Label(master, text="Password:")
        self.label_password.grid(row=1, column=0, padx=10, pady=5)

        self.entry_password = Entry(master, width=30, show="*")
        self.entry_password.grid(row=1, column=1, padx=10, pady=5)

        self.show_password_var = IntVar()
        self.checkbox_show_password = Checkbutton(master, text="Show Password", variable=self.show_password_var,
                                                 command=self.toggle_password_visibility)
        self.checkbox_show_password.grid(row=2, column=1, sticky='w', padx=10)

        self.btn_generate = Button(master, text="Generate Password", command=self.generate_password_gui)
        self.btn_generate.grid(row=3, column=0, columnspan=2, pady=5)

        self.btn_add = Button(master, text="Add/Save Password", command=self.add_password_gui)
        self.btn_add.grid(row=4, column=0, columnspan=2, pady=5)

        self.btn_get = Button(master, text="Get Password", command=self.get_password_gui)
        self.btn_get.grid(row=5, column=0, columnspan=2, pady=5)

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.entry_password.config(show="")
        else:
            self.entry_password.config(show="*")

    def generate_password_gui(self):
        length = simpledialog.askinteger("Password Length", "Enter password length (8-64):", minvalue=8, maxvalue=64)
        if length:
            new_password = generate_password(length)
            self.entry_password.delete(0, END)
            self.entry_password.insert(0, new_password)

    def add_password_gui(self):
        service = self.entry_service.get().strip()
        password = self.entry_password.get().strip()

        if not service or not password:
            messagebox.showwarning("Input Error", "Please enter both service and password.")
            return

        self.passwords[service] = password
        save_passwords(self.passwords, self.fernet)
        messagebox.showinfo("Success", f"Password for '{service}' saved!")
        self.entry_service.delete(0, END)
        self.entry_password.delete(0, END)

    def get_password_gui(self):
        service = self.entry_service.get().strip()
        if not service:
            messagebox.showwarning("Input Error", "Please enter a service name.")
            return

        password = self.passwords.get(service)
        if password:
            self.entry_password.delete(0, END)
            self.entry_password.insert(0, password)
            self.show_password_var.set(1)
            self.entry_password.config(show="")
            messagebox.showinfo("Password Found", f"Password for '{service}' retrieved.")
        else:
            messagebox.showerror("Not Found", f"No password found for '{service}'.")


def prompt_master_password():
    # Use a simple Tkinter dialog to ask master password
    root = Tk()
    root.withdraw()  # Hide main window
    while True:
        master_pw = simpledialog.askstring("Master Password", "Enter your master password:", show='*')
        if master_pw is None:
            # User cancelled
            root.destroy()
            return None
        if verify_master_password(master_pw):
            root.destroy()
            return master_pw
        else:
            messagebox.showerror("Incorrect Password", "Master password is incorrect. Try again.")


def main():
    master_password = prompt_master_password()
    if master_password is None:
        print("No master password entered. Exiting.")
        return

    fernet_key = get_fernet_key(master_password)
    fernet = Fernet(fernet_key)

    root = Tk()
    root.geometry("350x250")
    app = PasswordManagerApp(root, fernet)
    root.mainloop()


if __name__ == "__main__":
    main()
