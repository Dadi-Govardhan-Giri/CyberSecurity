
import base64
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

PBKDF2_ITERATIONS = 200_000  # increase if you want even stronger KDF

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password using PBKDF2-HMAC-SHA256."""
    return PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

def encrypt_aes_gcm(plaintext: str, password: str) -> str:
    """
    Encrypt a UTF-8 plaintext with AES-256-GCM.
    Returns a Base64 string that packs: salt || nonce || ciphertext || tag
    """
    salt = os.urandom(16)          # for PBKDF2
    key = derive_key(password, salt)
    nonce = os.urandom(12)         # 12 bytes recommended for GCM
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    packed = salt + nonce + ciphertext + tag
    return base64.b64encode(packed).decode('ascii')

def decrypt_aes_gcm(b64_blob: str, password: str) -> str:
    """
    Decrypt the Base64 blob produced by encrypt_aes_gcm.
    Expects: salt(16) || nonce(12) || ciphertext(...) || tag(16)
    """
    data = base64.b64decode(b64_blob)
    salt, rest = data[:16], data[16:]
    nonce, rest = rest[:12], rest[12:]
    tag = rest[-16:]
    ciphertext = rest[:-16]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

if __name__ == "__main__":
    print("=== AES-256-GCM Encrypt ===")
    password = input("Enter password: ")
    plaintext = input("Enter plaintext: ")

    b64_encrypted = encrypt_aes_gcm(plaintext, password)
    print("\nEncrypted (Base64):")
    print(b64_encrypted)

    # Optional quick check: try decrypting right away
    try:
        recovered = decrypt_aes_gcm(b64_encrypted, password)
        print("\nDecrypted back (sanity check): or ENTERED TEXT IS :")
        print(recovered)
    except Exception as e:
        print("\nDecryption check failed:", e)
