# AES-256 File Encryptor/Decryptor

## 📌 Introduction
This project is a secure file encryption and decryption tool using **AES-256-GCM** in Python. It provides a graphical user interface (GUI) built with **Tkinter**, allowing users to securely encrypt and decrypt files. It uses a **password-based key derivation function (PBKDF) with Scrypt** for added security.

## 🔑 Features
- **AES-256-GCM Encryption**: Ensures data confidentiality and integrity.
- **Secure Key Derivation (Scrypt)**: Prevents brute-force attacks.
- **Password Strength Checker**: Ensures strong passwords for encryption.
- **GUI with Tkinter**: Easy-to-use interface for selecting files.
- **File Integrity Verification**: Prevents tampering using authentication tags.
- **Progress Bar**: Visual indication during encryption/decryption.

## 🏗️ Installation
### **Prerequisites**
Ensure you have **Python 3.x** installed and install the required libraries:
```bash
pip install pycryptodome
```

## 🚀 Usage
### **Run the Application**
```bash
python aes_encryptor.py
```

### **Encrypt a File**
1. Select a file using the **Browse** button.
2. Enter a strong password (minimum 12 characters, including uppercase, lowercase, numbers, and symbols).
3. Confirm the password.
4. Click **Encrypt File**.
5. The encrypted file will be saved as `<filename>.enc`.

### **Decrypt a File**
1. Select an **encrypted file** (`.enc`).
2. Enter the same password used for encryption.
3. Click **Decrypt File**.
4. The decrypted file will be saved as `<filename>_decrypted`.

## 🔄 File Structure
| File | Description |
|------|------------|
| `aes_encryptor.py` | Main script containing encryption, decryption, and GUI. |
| `requirements.txt` | List of required Python dependencies. |

## 🔒 Security Implementation
### **Key Derivation Function (Scrypt)**
```python
def derive_key(password, salt):
    return scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)
```
- Uses a 256-bit key.
- Scrypt parameters prevent brute-force attacks.

### **AES-256-GCM Encryption**
```python
def encrypt_file(filepath, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
```
- **GCM Mode**: Provides both encryption and authentication.
- **Salt**: Ensures unique keys for different encryptions.
- **Tag**: Protects against tampering.

### **AES-256-GCM Decryption**
```python
def decrypt_file(filepath, password):
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
```
- **Authentication Check**: Ensures file integrity.
- **MAC Validation**: Prevents unauthorized modifications.

## 🛠️ Troubleshooting
| Issue | Solution |
|--------|----------|
| `MAC check failed` | Ensure the password is correct and file is not altered. |
| Encrypted file does not decrypt | Make sure the correct encryption order is followed (Salt → IV → Tag → Ciphertext). |
| GUI not responding | Run `python aes_encryptor.py` in the terminal to check for errors. |

## 📜 License
This project is licensed under the **MIT License**.

## 📞 Contact
For issues or improvements, feel free to reach out or contribute via GitHub!
