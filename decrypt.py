# -----------------------------------------------------------
#  Decrypt Stego Image (AES + LSB)
# -----------------------------------------------------------

from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
    img = Image.open(stego_image_path)
    if img.mode != "RGB":
        img = img.convert("RGB")
    pixels = list(img.getdata())
    bits = []
    for pix in pixels:
        r, g, b = pix
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)
    # First 32 bits = message length
    header_bits = bits[:32]
    msg_len = 0
    for bit in header_bits:
        msg_len = (msg_len << 1) | bit
    msg_bits = bits[32:32 + msg_len*8]
    msg_bytes = _bits_to_bytes(msg_bits)
    return msg_bytes

# -----------------------------------------------------------
#  AES Decryption Functions
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
    salt, iv, ciphertext = encrypted[:16], encrypted[16:32], encrypted[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    msg_padded = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = msg_padded[-1]
    return msg_padded[:-padding_length].decode()

# -----------------------------------------------------------
#  Main Program
# -----------------------------------------------------------

if __name__ == "__main__":
    print("=== Decrypt Stego Image ===")
    stego_image_path = input("Enter the path of the stego image: ")
    password = input("Enter the password used to encrypt the message: ")

    try:
        # Extract hidden bytes from image
        extracted_bytes = extract_message_lsb(stego_image_path)
        # Convert bytes -> string -> bytes for AES decryption
        extracted_hex = extracted_bytes.decode('utf-8')
        encrypted_bytes = bytes.fromhex(extracted_hex)
        # Decrypt
        decrypted_message = aes_decrypt(encrypted_bytes, password)
        print("\nDecrypted message:")
        print(decrypted_message)
    except Exception as e:
        print("Failed to decrypt. Check your password or stego image.")
        # Uncomment to see detailed error: print(e)
