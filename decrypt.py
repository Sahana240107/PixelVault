# -----------------------------------------------------------
#  Decrypt Stego Image (AES-GCM + LSB)
# -----------------------------------------------------------

import logging
from PIL import Image
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

logging.basicConfig(level=logging.INFO)

SALT_SIZE = 16
NONCE_SIZE = 12  # Recommended size for GCM
TAG_SIZE = 16

# -----------------------------------------------------------
#  Helper Functions
# -----------------------------------------------------------
def _bits_to_bytes(bits):
    assert len(bits) % 8 == 0
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)

# -----------------------------------------------------------
#  LSB Extraction
# -----------------------------------------------------------
def extract_message_lsb(stego_image_path):
    img = Image.open(stego_image_path).convert("RGB")
    pixels = list(img.getdata())
    bits = [bit & 1 for pixel in pixels for bit in pixel]

    msg_len = int(''.join(map(str, bits[:32])), 2)
    msg_bits = bits[32:32 + msg_len * 8]
    msg_bytes = _bits_to_bytes(msg_bits)
    return msg_bytes

# -----------------------------------------------------------
#  AES-GCM Decryption (Secure Mode)
# -----------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit AES key using PBKDF2-HMAC-SHA256."""
    return PBKDF2(password, salt, dkLen=32, count=100_000, hmac_hash_module=SHA256)

def aes_decrypt(encrypted: bytes, password: str) -> str:
    """
    Expected layout of encrypted data:
    [salt (16 bytes)] + [nonce (12 bytes)] + [ciphertext (...)] + [tag (16 bytes)]
    """
    salt = encrypted[:SALT_SIZE]
    nonce = encrypted[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = encrypted[-TAG_SIZE:]
    ciphertext = encrypted[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode('utf-8')

# -----------------------------------------------------------
#  Main Program
# -----------------------------------------------------------
if __name__ == "__main__":
    logging.info("=== Decrypt Stego Image (AES-GCM) ===")
    stego_image_path = input("Enter the path of the stego image: ")
    password = input("Enter the password used to encrypt the message: ")

    try:
        extracted_bytes = extract_message_lsb(stego_image_path)
        extracted_hex = extracted_bytes.decode('utf-8')
        encrypted_bytes = bytes.fromhex(extracted_hex)

        decrypted_message = aes_decrypt(encrypted_bytes, password)
        print("\n✅ Decrypted message:\n", decrypted_message)

    except Exception as e:
        logging.error("❌ Decryption failed. Check password or image integrity. Details: %s", e)
