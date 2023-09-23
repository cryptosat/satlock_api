from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from typing import List
import hashlib
from cryptography.hazmat.primitives import serialization, hashes, asymmetric
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

app = FastAPI()

class BackupKey(BaseModel):
    enc_backup_key: str
    address: str
    approved_guardians: List[str]

class GuardianApproveInput(BaseModel):
    guardian_public_key: str
    new_loser_address: str
    old_loser_address: str
    signed_hash: bytes

# Mock database for the addresses and their associated details.
KEYS_AND_GUARDIANS = {
    "sample_address": {
        "enc_backup_key": "sample_enc_backup_key",
        "guardians": ["guardian_api_key_1", "guardian_api_key_2"],
        "approvals": 0,
        "new_address": None
    }
}

# Mock private key for decryption
PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)


def verify_api_key(address: str, api_key: str = Header(None)):
    entry = KEYS_AND_GUARDIANS.get(address)
    if not entry or api_key not in entry["guardians"]:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return api_key

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.post("/storebackupkey", status_code=200)
def store_backup_key(key: BackupKey):
    KEYS_AND_GUARDIANS[key.address] = {
        "enc_backup_key": key.enc_backup_key,
        "guardians": key.approved_guardians,
        "approvals": 0,
        "new_address": None
    }
    return {"status": "Backup key, address, and guardians stored successfully"}

@app.post("/guardianapprove", status_code=200)
def guardian_approve(data: GuardianApproveInput, api_key: str = Header(None)):
    
    #Verify the API key for the provided address
    verify_api_key(data.old_loser_address, api_key)

    # Combine and hash the input parameters
    combined_data = data.guardian_public_key + data.new_loser_address + data.old_loser_address
    data_hash = hashlib.sha256(combined_data.encode()).digest()

    # Load the guardian's provided public key
    public_key = serialization.load_pem_public_key(data.guardian_public_key.encode(), backend=default_backend())

    # Verify the signature
    try:
        public_key.verify(
            data.signed_hash,
            data_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except:
        raise HTTPException(status_code=400, detail="Signature verification failed")

    return {"status": "Approved"}

@app.post("/restorekey")
def restore_key(old_user_address: str):
    GUARDIAN_THRESHOLD = 3
    entry = KEYS_AND_GUARDIANS.get(old_user_address)
       
    if not entry or entry["approvals"] < GUARDIAN_THRESHOLD:
        raise HTTPException(status_code=400, detail="Insufficient approvals or address not found")

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
    new_address_public_key = serialization.load_pem_public_key(entry["new_address"].encode(), backend=default_backend())
    encrypted_key = new_address_public_key.encrypt(
        decrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {"encrypted_key": encrypted_key}

class AnyInput(BaseModel):
    data: Any

@app.post("/test")
def test_endpoint(input_data: AnyInput):
    return {"received_data": input_data.data}

if __name__ == "__main__":
  import uvicorn
  uvicorn.run(app, host="127.0.0.1", port=9000)