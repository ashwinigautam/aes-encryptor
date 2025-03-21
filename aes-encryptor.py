import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
import threading
import time

# Constants
KEY_SIZE = 32   # 256-bit AES
IV_SIZE = 12    # Recommended for GCM
SALT_SIZE = 16
TAG_SIZE = 16

# Generate a strong key using Scrypt (Argon2-like)
def derive_key(password, salt):
    return scrypt(password.encode(), salt, KEY_SIZE, N=2**14, r=8, p=1)

# Password strength checker
def is_strong_password(password):
    return (
        len(password) >= 12 and
        any(c.islower() for c in password) and
        any(c.isupper() for c in password) and
        any(c.isdigit() for c in password) and
        any(c in "!@#$%^&*()-_=+" for c in password)
    )

# Encrypt file with AES-256-GCM
def encrypt_file(filepath, password):
    if not is_strong_password(password):
        messagebox.showerror("Error", "Weak password! Use at least 12 characters with uppercase, lowercase, numbers, and symbols.")
        return

    progress_bar.start(10)
    try:
        salt = os.urandom(SALT_SIZE)
        key = derive_key(password, salt)
        iv = os.urandom(IV_SIZE)

        cipher = AES.new(key, AES.MODE_GCM, iv)
        
        with open(filepath, "rb") as f:
            plaintext = f.read()

        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        encrypted_filepath = filepath + ".enc"
        with open(encrypted_filepath, "wb") as f:
            f.write(salt + iv + tag + ciphertext)  # Correct order: salt, IV, tag, ciphertext

        time.sleep(1)
        progress_bar.stop()
        messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {encrypted_filepath}")
    except Exception as e:
        progress_bar.stop()
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")


# Decrypt file with AES-256-GCM
def decrypt_file(filepath, password):
    progress_bar.start(10)
    try:
        with open(filepath, "rb") as f:
            salt = f.read(SALT_SIZE)
            iv = f.read(IV_SIZE)
            tag = f.read(TAG_SIZE)
            ciphertext = f.read()  # Remaining bytes are ciphertext

        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, iv)

        plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # Ensure correct order

        decrypted_filepath = filepath.replace(".enc", "_decrypted")
        with open(decrypted_filepath, "wb") as f:
            f.write(plaintext)

        time.sleep(1)
        progress_bar.stop()
        messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {decrypted_filepath}")
    except ValueError as e:
        progress_bar.stop()
        messagebox.showerror("Error", f"Decryption failed: Incorrect password or file modified.\n\n{str(e)}")
    except Exception as e:
        progress_bar.stop()
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")


# GUI Setup
def browse_file():
    file_path = filedialog.askopenfilename()
    entry_file.delete(0, tk.END)
    entry_file.insert(0, file_path)

def toggle_password():
    if entry_password.cget("show") == "*":
        entry_password.config(show="")
        entry_password_confirm.config(show="")
        btn_show_password.config(text="🙈 Hide Password")
    else:
        entry_password.config(show="*")
        entry_password_confirm.config(show="*")
        btn_show_password.config(text="👀 Show Password")

def start_encryption():
    file_path = entry_file.get()
    password = entry_password.get()
    confirm_password = entry_password_confirm.get()

    if not file_path:
        messagebox.showerror("Error", "Please select a file to encrypt.")
        return
    if password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match!")
        return

    threading.Thread(target=encrypt_file, args=(file_path, password)).start()

def start_decryption():
    file_path = entry_file.get()
    password = entry_password.get()

    if not file_path:
        messagebox.showerror("Error", "Please select a file to decrypt.")
        return

    threading.Thread(target=decrypt_file, args=(file_path, password)).start()

# GUI Design
root = tk.Tk()
root.title("🔐 Secure AES-256 File Encryptor")
root.geometry("500x450")
root.resizable(False, False)
root.configure(bg="#2C3E50")

frame = tk.Frame(root, bg="#34495E", padx=20, pady=20)
frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

ttk.Label(frame, text="📁 Select File:", background="#34495E", foreground="white").pack(pady=5)
entry_file = ttk.Entry(frame, width=50)
entry_file.pack()
ttk.Button(frame, text="🔍 Browse", command=browse_file).pack(pady=5)

ttk.Label(frame, text="🔑 Enter Password:", background="#34495E", foreground="white").pack(pady=5)
entry_password = ttk.Entry(frame, width=35, show="*")
entry_password.pack()

ttk.Label(frame, text="🔁 Confirm Password:", background="#34495E", foreground="white").pack(pady=5)
entry_password_confirm = ttk.Entry(frame, width=35, show="*")
entry_password_confirm.pack()

btn_show_password = ttk.Button(frame, text="👀 Show Password", command=toggle_password)
btn_show_password.pack(pady=5)

ttk.Button(frame, text="🔐 Encrypt File", command=start_encryption, style="TButton").pack(pady=5)
ttk.Button(frame, text="🔓 Decrypt File", command=start_decryption, style="TButton").pack(pady=5)

progress_bar = ttk.Progressbar(frame, length=350, mode="indeterminate")
progress_bar.pack(pady=5)

root.mainloop()