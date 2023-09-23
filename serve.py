from flask import Flask, request, jsonify
from flask_cors import CORS
from typing import List, Any
import hashlib
from cryptography.hazmat.primitives import serialization, hashes, asymmetric
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import json

app = Flask(__name__)
CORS(app)

# Generate private key
PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Mock database for the addresses and their associated details
KEYS_AND_GUARDIANS = {}

@app.route('/', methods=['GET'])
def read_root():
    return jsonify({"Hello": "World"})

@app.route('/storebackupkey', methods=['POST'])
def store_backup_key():
    key = request.json

    KEYS_AND_GUARDIANS[key['address']] = {
        "enc_backup_key": key['enc_backup_key'],
        "guardians": key['approved_guardians'],
        "approvals": 0,
        "new_address": None
    }

    print('State of key storage:')
    print(KEYS_AND_GUARDIANS)

    return jsonify({"status": "Backup key, address, and guardians stored successfully"})

@app.route('/guardianapprove', methods=['POST'])
def guardian_approve():
    data = request.json
    api_key = request.headers.get('api_key')

    # Manually calling the verify function
    # your implementation here...

    # Implement your existing logic here...

    return jsonify({"status": "Approved"})

@app.route('/restorekey', methods=['POST'])
def restore_key():
    old_user_address = request.json['old_user_address']

    # Implement your existing logic here...

    return jsonify({"encrypted_key": "some_encrypted_key"})

@app.route('/test', methods=['POST'])
def test_endpoint():
    input_data = request.json['data']
    return jsonify({"received_data": input_data})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=9000)
