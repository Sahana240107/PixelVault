from flask import Flask, request, send_file, render_template
from io import BytesIO
from PIL import Image
import traceback

# Import encryption/decryption functions
from encrypt import aes_encrypt
from decrypt import aes_decrypt

app = Flask(__name__)

# ------------------- CONSTANTS -------------------
ENCRYPT_TEMPLATE = 'encrypt.html'
DECRYPT_TEMPLATE = 'decrypt.html'
MSG_START_TAG = '[MSG_START]'

# ------------------- HOME -------------------
@app.route('/')
def home():
    return render_template('index.html')


# ------------------- ENCRYPT -------------------
@app.route('/encrypt', methods=['GET'])
def encrypt_page():
    return render_template(ENCRYPT_TEMPLATE)


@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    try:
        image_file = request.files.get('image')
        message = request.form.get('message', '')
        password = request.form.get('password', '')

        if not image_file or not message or not password:
            return render_template(ENCRYPT_TEMPLATE, error="Missing image, message, or password.")

        img = Image.open(image_file.stream)
        if img.mode != "RGB":
            img = img.convert("RGB")

        secure_message = MSG_START_TAG + message
        encrypted_bytes = aes_encrypt(secure_message, password)
        encrypted_hex = encrypted_bytes.hex()

        pixels = list(img.getdata())
        width, height = img.size
        capacity_bits = len(pixels) * 3

        header_bits = [(len(encrypted_hex.encode()) >> i) & 1 for i in reversed(range(32))]
        msg_bits = []
        for b in encrypted_hex.encode():
            for i in reversed(range(8)):
                msg_bits.append((b >> i) & 1)
        all_bits = header_bits + msg_bits

        if len(all_bits) > capacity_bits:
            return render_template(ENCRYPT_TEMPLATE, error="Message too large for image!")

        bit_idx = 0
        new_pixels = []
        for r, g, b in pixels:
            if bit_idx < len(all_bits):
                r = (r & ~1) | all_bits[bit_idx]
                bit_idx += 1
            if bit_idx < len(all_bits):
                g = (g & ~1) | all_bits[bit_idx]
                bit_idx += 1
            if bit_idx < len(all_bits):
                b = (b & ~1) | all_bits[bit_idx]
                bit_idx += 1
            new_pixels.append((r, g, b))

        stego_img = Image.new("RGB", (width, height))
        stego_img.putdata(new_pixels)

        output_stream = BytesIO()
        stego_img.save(output_stream, format='PNG')
        output_stream.seek(0)

        return send_file(
            output_stream,
            mimetype='image/png',
            as_attachment=True,
            download_name='stego.png'
        )

    except Exception as e:
        print("Encryption error:", traceback.format_exc())
        return render_template(ENCRYPT_TEMPLATE, error=f"Encryption error: {e}")


# ------------------- DECRYPT -------------------
@app.route('/decrypt', methods=['GET'])
def decrypt_page():
    return render_template(DECRYPT_TEMPLATE)


@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    try:
        image_file = request.files.get('image')
        password = request.form.get('password', '')

        if not image_file or not password:
            return render_template(DECRYPT_TEMPLATE, error="Please upload an image and enter password.")

        img = Image.open(image_file.stream)
        if img.mode != "RGB":
            img = img.convert("RGB")

        # Extract bits from image
        pixels = list(img.getdata())
        bits = []
        for r, g, b in pixels:
            bits.extend([r & 1, g & 1, b & 1])

        header_bits = bits[:32]
        msg_len = 0
        for bit in header_bits:
            msg_len = (msg_len << 1) | bit

        msg_bits = bits[32:32 + msg_len * 8]
        msg_bytes = bytearray()
        for i in range(0, len(msg_bits), 8):
            byte = 0
            for bit in msg_bits[i:i + 8]:
                byte = (byte << 1) | bit
            msg_bytes.append(byte)

        extracted_hex = msg_bytes.decode('utf-8', errors='ignore')
        encrypted_bytes = bytes.fromhex(extracted_hex)

        try:
            message = aes_decrypt(encrypted_bytes, password)
        except Exception:
            return render_template(DECRYPT_TEMPLATE, error="Incorrect password or corrupted image.")

        if not message.startswith(MSG_START_TAG):
            return render_template(DECRYPT_TEMPLATE, error="Incorrect password or corrupted image.")

        clean_message = message.replace(MSG_START_TAG, "", 1)
        return render_template(DECRYPT_TEMPLATE, message=clean_message)

    except Exception as e:
        print("Decryption error:", traceback.format_exc())
        return render_template(DECRYPT_TEMPLATE, error=f"Decryption failed: {e}")


# ------------------- RUN APP -------------------
if __name__ == '__main__':
    app.run(debug=True, port=5000)
