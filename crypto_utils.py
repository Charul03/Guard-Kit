from cryptography.fernet import Fernet
import os

def generate_key() -> str:
    key = Fernet.generate_key().decode()
    print(f"🔑 New encryption key generated:\n{key}")
    return key

def encrypt_file(filepath: str, key: str) -> str:
    fernet = Fernet(key.encode())

    # Check file existence
    if not os.path.exists(filepath):
        return f"❌ Error: File '{filepath}' not found."

    with open(filepath, 'rb') as f:
        data = f.read()

    token = fernet.encrypt(data)
    out = filepath + '.enc'

    with open(out, 'wb') as fo:
        fo.write(token)

    return f"✅ File successfully encrypted!\n📁 Encrypted file saved as: {out}"

def decrypt_file(enc_filepath: str, key: str) -> str:
    fernet = Fernet(key.encode())

    if not os.path.exists(enc_filepath):
        return f"❌ Error: Encrypted file '{enc_filepath}' not found."

    with open(enc_filepath, 'rb') as f:
        token = f.read()

    try:
        data = fernet.decrypt(token)
    except Exception:
        return "⚠️ Decryption failed. Please check your key or file."

    out = enc_filepath.replace('.enc', '') + '.decrypted'

    with open(out, 'wb') as fo:
        fo.write(data)

    return f"✅ File successfully decrypted!\n📁 Decrypted file saved as: {out}"
