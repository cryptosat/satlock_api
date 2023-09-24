from flask import Flask, abort, request, jsonify
from flask_cors import CORS
from typing import List, Any
import hashlib
from cryptography.hazmat.primitives import serialization, hashes, asymmetric
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import json
import os

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

STORAGE_FILE = 'cryptosat_state.json'

def save_state():
    with open(STORAGE_FILE, 'w') as f:
        json.dump(KEYS_AND_GUARDIANS, f)

def load_state():
    global KEYS_AND_GUARDIANS
    if os.path.exists(STORAGE_FILE):
        # Reading data back
        with open(STORAGE_FILE, 'r') as f:
            KEYS_AND_GUARDIANS = json.load(f)
        
        # Now my_dict is a dictionary containing the data from the JSON file

@app.route('/', methods=['GET'])
def read_root():
    return jsonify({"Hello": "World"})

@app.route('/storebackupkey', methods=['POST'])
def store_backup_key():
    print('store_backup_key')
    key = request.json

    KEYS_AND_GUARDIANS[key['address'].lower()] = {
        "enc_backup_key": key['enc_backup_key'],
        "guardians": key['approved_guardians'],
        "approvals": 0,
        "new_address": None
    }

    print('State of key storage:')
    print(KEYS_AND_GUARDIANS)
    save_state()

    return jsonify({"status": "Backup key, address, and guardians stored successfully"})

@app.route('/guardianapprove', methods=['POST'])
def guardian_approve():
    print('guardian_approve')
    data = request.json
    old_loser_address = data['old_loser_address'].lower()

    # Verify the Guardian public key for the provided address
    # TODO: Add that each Guardian can only approve once
    entry = KEYS_AND_GUARDIANS.get(old_loser_address)
    if not entry or data['guardian_public_key'] not in entry['guardians']:
        return {"status": "Not an approved guardian for the provided wallet"}, 401

    # Combine and hash the input parameters
    combined_data = data['old_loser_address'] + data['guardian_public_key'] + data['new_loser_address'];
    data_hash = hashlib.sha256(combined_data.encode()).digest()

    # TODO: Load the guardian's provided public key
    # public_key = serialization.load_pem_public_key(data['guardian_public_key'].encode(), 
    #                                                backend=default_backend())
    public_key = data['guardian_public_key']

    
    # TODO: Verify the signature
    # try:
    #     public_key.verify(
    #         bytes.fromhex(data['signed_hash']),
    #         data_hash,
    #         padding.PKCS1v15(),
    #         hashes.SHA256()
    #     )
    # except:
    #     return {"status": "Signature verification failed"}, 400

    # Assuming the signature is valid, do further processing here, for example:
    # For now, we don't check that the approvals are coming from distinct guardians
    # This check MUST be added
    KEYS_AND_GUARDIANS[old_loser_address]['approvals'] += 1
    save_state()

    return {"status": "Approved"}, 200

@app.route('/recoverkey', methods=['POST'])
def restore_key():
    GUARDIAN_THRESHOLD = 2
    print('restorekey')
    
    # Replace this with how you're getting the old_user_address
    old_loser_address = request.json['old_loser_address'].lower()

    entry = KEYS_AND_GUARDIANS.get(old_loser_address)
    
    if not entry:
        abort(400, "Address not found")
    
    if entry['approvals'] < GUARDIAN_THRESHOLD:
        abort(400, "Insufficient approvals")

    #TODO: Encrypt recovered key with newly provided KEY
    # Decrypt the backup key
    # decrypted_key = PRIVATE_KEY.decrypt(
    #     entry["enc_backup_key"].encode(),
    #     padding.OAEP(
    #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #         algorithm=hashes.SHA256(),
    #         label=None
    #     )
    # )
    decrypted_key = entry['enc_backup_key']
    
    # Encrypt the decrypted key with the provided RSA public key (new_address)
    # new_address_public_key = serialization.load_pem_public_key(entry["new_address"].encode(), 
    #                                                            backend=default_backend())
    # encrypted_key = new_address_public_key.encrypt(
    #     decrypted_key,
    #     padding.OAEP(
    #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #         algorithm=hashes.SHA256(),
    #         label=None
    #     )
    # )

    return {'encrypted_key': decrypted_key}, 200

if __name__ == "__main__":
    load_state()
    print(KEYS_AND_GUARDIANS)
    app.run(debug=True, host='0.0.0.0', port=9000)
