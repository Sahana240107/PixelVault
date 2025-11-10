from flask import Flask, request, send_file, jsonify, render_template
from io import BytesIO
from PIL import Image
import traceback

# Import your existing encryption/decryption functions
from encrypt import aes_encrypt, embed_message_lsb
from decrypt import aes_decrypt, extract_message_lsb

# ------------------- APP INITIALIZATION -------------------
app = Flask(__name__)

# ✅ Secure Flask configuration
app.config['SECRET_KEY'] = 'your-secure-random-key'  # Required for CSRF protection

# ✅ Enable CSRF protection
try:
    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect(app)
except ImportError:
    csrf = None
    print("⚠️ Flask-WTF not installed. Run: pip install flask-wtf for CSRF protection.")

# ------------------- ROUTES -------------------

@app.route('/')
def home():
    """Render home page."""
    return render_template('index.html')


@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt_route():
    """Handle AES + LSB encryption."""
    if request.method == 'GET':
        return render_template('encrypt.html')

    try:
        # Retrieve data from form
        message = request.form['message']
        password = request.form['password']
        image_file = request.files['image']

        # Open image
        image = Image.open(image_file)

        # Encrypt message using AES
        ciphertext, salt, iv = aes_encrypt(message, password)

        # Embed the encrypted message using LSB
        stego_image = embed_message_lsb(image, ciphertext, salt, iv)

        # Save to buffer
        output = BytesIO()
        stego_image.save(output, format='PNG')
        output.seek(0)

        return send_file(output, mimetype='image/png', as_attachment=True, download_name='stego_image.png')

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt_route():
    """Handle AES + LSB decryption."""
    if request.method == 'GET':
        return render_template('decrypt.html')

    try:
        # Retrieve data from form
        password = request.form['password']
        image_file = request.files['image']

        # Open image
        image = Image.open(image_file)

        # Extract encrypted message, salt, and iv
        ciphertext, salt, iv = extract_message_lsb(image)

        # Decrypt message
        plaintext = aes_decrypt(ciphertext, password, salt, iv)

        return jsonify({'message': plaintext})

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ------------------- ERROR HANDLERS -------------------

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Page not found'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal Server Error'}), 500


# ------------------- ENTRY POINT -------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
