from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__)
CORS(app)

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    text = data.get('text')
    method = data.get('method')
    key = data.get('key')

    if not text or not method:
        return jsonify({'message': 'Text and method are required.'}), 400

    try:
        if method == 'AES':
            encrypted_text = aes_encrypt(text, key)
        elif method == 'DES':
            encrypted_text = des_encrypt(text, key)
        elif method == 'RSA':
            encrypted_text = rsa_encrypt(text)
        else:
            return jsonify({'message': 'Unsupported encryption method.'}), 400

        return jsonify({'encryptedText': encrypted_text})
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    text = data.get('text')
    method = data.get('method')
    key = data.get('key')

    if not text or not method:
        return jsonify({'message': 'Text and method are required.'}), 400

    try:
        if method == 'AES':
            decrypted_text = aes_decrypt(text, key)
        elif method == 'DES':
            decrypted_text = des_decrypt(text, key)
        elif method == 'RSA':
            decrypted_text = rsa_decrypt(text)
        else:
            return jsonify({'message': 'Unsupported decryption method.'}), 400

        return jsonify({'decryptedText': decrypted_text})
    except Exception as e:
        return jsonify({'message': str(e)}), 500

def aes_encrypt(plain_text, key):
    if not key:
        raise ValueError('Key is required for AES encryption.')

    key_bytes = key.encode('utf-8')
    if len(key_bytes) not in [16, 24, 32]:
        raise ValueError('Key must be 16, 24, or 32 bytes long.')

    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    padded_text = pad(plain_text.encode('utf-8'), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_text)
    encrypted_data = base64.b64encode(iv + encrypted_bytes).decode('utf-8')
    return encrypted_data

def aes_decrypt(encrypted_text, key):
    if not key:
        raise ValueError('Key is required for AES decryption.')

    key_bytes = key.encode('utf-8')
    if len(key_bytes) not in [16, 24, 32]:
        raise ValueError('Key must be 16, 24, or 32 bytes long.')

    encrypted_data = base64.b64decode(encrypted_text)
    iv = encrypted_data[:16]
    encrypted_bytes = encrypted_data[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    decrypted_text = unpad(decrypted_padded, AES.block_size).decode('utf-8')
    return decrypted_text

def des_encrypt(plain_text, key):
    if not key:
        raise ValueError('Key is required for DES encryption.')

    key_bytes = key.encode('utf-8')
    if len(key_bytes) != 8:
        raise ValueError('Key must be 8 bytes long for DES.')

    iv = get_random_bytes(8)
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
    padded_text = pad(plain_text.encode('utf-8'), DES.block_size)
    encrypted_bytes = cipher.encrypt(padded_text)
    encrypted_data = base64.b64encode(iv + encrypted_bytes).decode('utf-8')
    return encrypted_data

def des_decrypt(encrypted_text, key):
    if not key:
        raise ValueError('Key is required for DES decryption.')

    key_bytes = key.encode('utf-8')
    if len(key_bytes) != 8:
        raise ValueError('Key must be 8 bytes long for DES.')

    encrypted_data = base64.b64decode(encrypted_text)
    iv = encrypted_data[:8]
    encrypted_bytes = encrypted_data[8:]
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    decrypted_text = unpad(decrypted_padded, DES.block_size).decode('utf-8')
    return decrypted_text

def rsa_encrypt(plain_text):
    encrypted = public_key.encrypt(
        plain_text.encode('utf-8'),
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_data = base64.b64encode(encrypted).decode('utf-8')
    return encrypted_data

def rsa_decrypt(encrypted_text):
    encrypted_data = base64.b64decode(encrypted_text)
    decrypted = private_key.decrypt(
        encrypted_data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    decrypted_text = decrypted.decode('utf-8')
    return decrypted_text

if __name__ == '__main__':
    app.run(debug=True)
