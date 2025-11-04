# -----------------------------------------------------------
#  Secure LSB Steganography with AES Encryption (Python)
# -----------------------------------------------------------

from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# -----------------------------------------------------------
#  Helper Functions
# -----------------------------------------------------------

def _int_to_bits(n, bit_length):
    return [(n >> i) & 1 for i in reversed(range(bit_length))]

def _bytes_to_bits(data_bytes):
    bits = []
    for b in data_bytes:
        bits.extend(_int_to_bits(b, 8))
    return bits

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
#  LSB Steganography Functions
# -----------------------------------------------------------

def embed_message_lsb(cover_image_path, out_path, message):
    img = Image.open(cover_image_path)
    if img.mode != "RGB":
        img = img.convert("RGB")
    pixels = list(img.getdata())
    width, height = img.size
    capacity_bits = len(pixels) * 3  # 3 bits per pixel

    if isinstance(message, str):
        message_bytes = message.encode("utf-8")
    else:
        message_bytes = message

    header_bits = _int_to_bits(len(message_bytes), 32)
    message_bits = _bytes_to_bits(message_bytes)
    total_bits = len(header_bits) + len(message_bits)
    if total_bits > capacity_bits:
        raise ValueError("Message too large for this image!")
    all_bits = header_bits + message_bits
    bit_idx = 0
    new_pixels = []
    for pix in pixels:
        if bit_idx >= total_bits:
            new_pixels.append(pix)
            continue
        r, g, b = pix
        if bit_idx < total_bits:
            r = (r & ~1) | all_bits[bit_idx]; bit_idx += 1
        if bit_idx < total_bits:
            g = (g & ~1) | all_bits[bit_idx]; bit_idx += 1
        if bit_idx < total_bits:
            b = (b & ~1) | all_bits[bit_idx]; bit_idx += 1
        new_pixels.append((r, g, b))
    stego = Image.new("RGB", (width, height))
    stego.putdata(new_pixels)
    stego.save(out_path)
    print(f"[+] Saved stego image as {out_path}")

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
    header_bits = bits[:32]
    msg_len = 0
    for bit in header_bits:
        msg_len = (msg_len << 1) | bit
    msg_bits = bits[32:32 + msg_len*8]
    msg_bytes = _bits_to_bytes(msg_bits)
    return msg_bytes

# -----------------------------------------------------------
#  AES Encryption Functions
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

def aes_encrypt(message: str, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    msg_bytes = message.encode()
    from cryptography.hazmat.primitives import padding

# Apply PKCS7 padding
padder = padding.PKCS7(128).padder()   # 128 bits = 16 bytes (AES block size)
padded_data = padder.update(msg_bytes) + padder.finalize()

# Encrypt
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return salt + iv + ciphertext

def aes_decrypt(encrypted: bytes, password: str) -> str:
    salt, iv, ciphertext = encrypted[:16], encrypted[16:32], encrypted[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    from cryptography.hazmat.primitives import padding

msg_padded = decryptor.update(ciphertext) + decryptor.finalize()

# Remove PKCS7 padding securely
unpadder = padding.PKCS7(128).unpadder()
unpadded_data = unpadder.update(msg_padded) + unpadder.finalize()
return unpadded_data.decode()

# -----------------------------------------------------------
#  Main Program
# -----------------------------------------------------------

if __name__ == "__main__":
    print("=== Secure Image Steganography ===")
    cover_path = input("Enter path of the cover image (PNG/BMP recommended): ")
    message = input("Enter the message you want to hide: ")
    password = input("Enter a password to protect the message: ")
    output_path = input("Enter filename for the output stego image (e.g., stego.png): ")

    # Encrypt message
    encrypted_bytes = aes_encrypt(message, password)
    # Embed in image
    embed_message_lsb(cover_path, output_path, encrypted_bytes.hex())

    print("\n[+] Encryption and embedding complete!")

    # Verification (optional)
    extracted_hex = extract_message_lsb(output_path).decode('utf-8')
    encrypted_bytes_extracted = bytes.fromhex(extracted_hex)
    decrypted_message = aes_decrypt(encrypted_bytes_extracted, password)
    print("\n[Verification] Decrypted message from stego image:")
    print(decrypted_message)

