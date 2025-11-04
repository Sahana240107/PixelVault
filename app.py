from flask import Flask, request, send_file, jsonify, render_template
from io import BytesIO
from PIL import Image
import traceback

# import your existing functions
from encrypt import aes_encrypt, embed_message_lsb
from decrypt import aes_decrypt, extract_message_lsb

app = Flask(__name__)

# ------------------- HOME -------------------
@app.route('/')
def home():
    return render_template('index.html')


# ------------------- ENCRYPT -------------------
# GET → show form
@app.route('/encrypt', methods=['GET'])
def encrypt_page():
    return render_template('encrypt.html')

# POST → process encryption
@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    try:
        image_file = request.files.get('image')
        message = request.form.get('message', '')
        password = request.form.get('password', '')

        if not image_file or not message or not password:
            return "Missing image, message, or password.", 400

        img = Image.open(image_file.stream)
        if img.mode != "RGB":
            img = img.convert("RGB")

        # Encrypt the message with marker
        secure_message = "[MSG_START]" + message
        encrypted_bytes = aes_encrypt(secure_message, password)
        encrypted_hex = encrypted_bytes.hex()

        # Embed into image
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
            return "Message too large for image!", 400

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

        # Send image as download
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
        return f"Encryption error: {e}", 500


# ------------------- DECRYPT -------------------
# GET → show form
@app.route('/decrypt', methods=['GET'])
def decrypt_page():
    return render_template('decrypt.html')

# POST → process decryption
@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    try:
        image_file = request.files.get('image')
        password = request.form.get('password', '')

        if not image_file or not password:
            return jsonify({"error": "Missing image or password."}), 400

        img = Image.open(image_file.stream)
        if img.mode != "RGB":
            img = img.convert("RGB")

        # Extract LSB bits
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
            return jsonify({"error": "Incorrect password or corrupted image."}), 401

        if not message.startswith("[MSG_START]"):
            return jsonify({"error": "Incorrect password or corrupted image."}), 401

        clean_message = message.replace("[MSG_START]", "", 1)
        return jsonify({"message": clean_message})

    except Exception as e:
        print("Decryption error:", traceback.format_exc())
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
