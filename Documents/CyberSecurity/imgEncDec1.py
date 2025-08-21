import hashlib

from Crypto.Cipher import AES

password = "SRIVARDHAN"

# Convert to 16-byte AES key by padding
key = password.ljust(16, "X").encode("utf-8")  # 'XXXXXXXX' added

# Read image as binary
with open("iimg.jpg", "rb") as f:
    data = f.read()

# Pad data
def pad(data):
    return data + b"\0" * (16 - len(data) % 16)

def unpad(data):
    return data.rstrip(b"\0")

cipher = AES.new(key, AES.MODE_ECB)

# Encrypt
encrypted = cipher.encrypt(pad(data))
with open("encrypted1.img", "wb") as f:
    f.write(encrypted)

# Decrypt
decrypted = unpad(cipher.decrypt(encrypted))
with open("decrypted1.jpg", "wb") as f:
    f.write(decrypted)
