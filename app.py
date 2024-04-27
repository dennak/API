from flask import Flask, request, send_file, jsonify, abort
from flask_cors import CORS  # Import CORS
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import time
import os


# Define a base directory to store files
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
CORS(app)  # Setup CORS, adjust origins as necessary

def key_from_password(password: str, salt: bytes) -> bytes:
    """Generate a key from a password and salt."""
    password_bytes = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

@app.route('/encrypt', methods=['POST'])
def encrypt_image():
    try:
        current_time_seconds = time.time()
        current_time_milliseconds = int(current_time_seconds)
        file = request.files['file']
        f_name = file.filename.split('.')[0]
        FILE_EXTENSION = file.filename.split('.')[1]
        password = request.form['password']
        salt = os.urandom(16)
        key = key_from_password(password, salt)
        fernet = Fernet(key)
        original_data = file.read()
        encrypted_data = fernet.encrypt(original_data)

        ENCRYPTED_FILE_PATH = os.path.join(BASE_DIR, f'{f_name}_{str(current_time_milliseconds)}{1 if FILE_EXTENSION=='jpg' else 2}.enc')

        with open(ENCRYPTED_FILE_PATH, 'wb') as enc_file:
            enc_file.write(salt + encrypted_data)  # Store salt with encrypted data
        return send_file(ENCRYPTED_FILE_PATH, as_attachment=True, download_name=f'{f_name}_{str(current_time_milliseconds)}.enc')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt_image():
    try:
        file = request.files['file']
        f_name = file.filename.split('.')[0]
        password = request.form['password']
        file_content = file.read()
        salt = file_content[:16]
        encrypted_data = file_content[16:]
        key = key_from_password(password, salt)
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)

        DECRYPTED_FILE_PATH = os.path.join(BASE_DIR, f'{f_name}.{'jpg' if f_name[-1]==str(1) else 'png'}')

        with open(DECRYPTED_FILE_PATH, 'wb') as file:
            file.write(decrypted_data)
        return send_file(DECRYPTED_FILE_PATH, as_attachment=True, download_name=f'{f_name}.{'jpg' if f_name[-1]==str(1) else 'png'}')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
