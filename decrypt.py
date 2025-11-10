# -----------------------------------------------------------
#  Decrypt Stego Image (AES + LSB)
# -----------------------------------------------------------

import logging
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logging.basicConfig(level=logging.INFO)

SALT_SIZE = 16
IV_SIZE = 16

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
#  AES Decryption
# -----------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def aes_decrypt(encrypted: bytes, password: str) -> str:
    salt = encrypted[:SALT_SIZE]
    iv = encrypted[SALT_SIZE:SALT_SIZE+IV_SIZE]
    ciphertext = encrypted[SALT_SIZE+IV_SIZE:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    msg_padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    msg = unpadder.update(msg_padded) + unpadder.finalize()

    return msg.decode()

# -----------------------------------------------------------
#  Main Program
# -----------------------------------------------------------
if __name__ == "__main__":
    logging.info("=== Decrypt Stego Image ===")
    stego_image_path = input("Enter the path of the stego image: ")
    password = input("Enter the password used to encrypt the message: ")

    try:
        extracted_bytes = extract_message_lsb(stego_image_path)
        extracted_hex = extracted_bytes.decode('utf-8')
        encrypted_bytes = bytes.fromhex(extracted_hex)
        decrypted_message = aes_decrypt(encrypted_bytes, password)
        print("\nDecrypted message:\n", decrypted_message)
    except Exception as e:
        logging.error("Decryption failed. Check your password or stego image. Details: %s", e)
