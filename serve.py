from flask import Flask, abort, request, jsonify
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
    api_key = request.headers.get('Authorization')

    old_loser_address = data['old_loser_address']

    # Verify the API key for the provided address
    entry = KEYS_AND_GUARDIANS.get(old_loser_address)
    if not entry or api_key not in entry['guardians']:
        return {"status": "Not authenticated"}, 401

    # Combine and hash the input parameters
    combined_data = data['guardian_public_key'] + data['new_loser_address'] + data['old_loser_address']
    data_hash = hashlib.sha256(combined_data.encode()).digest()

    # Load the guardian's provided public key
    public_key = serialization.load_pem_public_key(data['guardian_public_key'].encode(), backend=default_backend())

    # Verify the signature
    try:
        public_key.verify(
            bytes.fromhex(data['signed_hash']),
            data_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except:
        return {"status": "Signature verification failed"}, 400

    # Assuming the signature is valid, do further processing here, for example:
    entry['approvals'] += 1

    return {"status": "Approved"}

@app.route('/restorekey', methods=['POST'])
def restore_key():
    GUARDIAN_THRESHOLD = 3
    
    # Replace this with how you're getting the old_user_address
    old_user_address = request.json
    
    entry = KEYS_AND_GUARDIANS.get(old_user_address)
    
    if not entry or entry["approvals"] < GUARDIAN_THRESHOLD:
        abort(400, "Insufficient approvals or address not found")

    # Decrypt the backup key
    decrypted_key = PRIVATE_KEY.decrypt(
        entry["enc_backup_key"].encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Encrypt the decrypted key with the provided RSA public key (new_address)
    new_address_public_key = serialization.load_pem_public_key(entry["new_address"].encode(), 
                                                               backend=default_backend())
    # encrypted_key = new_address_public_key.encrypt(
    #     decrypted_key,
    #     padding.OAEP(
    #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #         algorithm=hashes.SHA256(),
    #         label=None
    #     )
    # )

    return {'encrypted_key': decrypted_key}

@app.route('/test', methods=['POST'])
def test_endpoint():
    input_data = request.json['data']
    return jsonify({"received_data": input_data})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=9000)
