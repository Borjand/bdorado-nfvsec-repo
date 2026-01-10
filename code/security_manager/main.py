from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import json
import os
import logging
import base64
from kafka import KafkaProducer

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

app = FastAPI()
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s')

BROKER_ADDRESS = os.getenv("BROKER_ADDRESS", "localhost:9092")
KEYS_DIR = os.getenv("KEYS_DIR", "/app/keys")
TOPOLOGY_TOPIC = os.getenv("TOPOLOGY_TOPIC", "vnffg_topic")


# Toggle crypto emulation without code changes
EMULATE_CRYPTO = os.getenv("EMULATE_CRYPTO", "1") == "1"

# Expected key files inside the image
SESSION_KEY_FILE = os.path.join(KEYS_DIR, "session_key.b64")
RSA_PUB_FILE = os.path.join(KEYS_DIR, "rsa_pub.pem")
SIGN_PRIV_FILE = os.path.join(KEYS_DIR, "sign_priv.pem")

def _load_session_key() -> bytes:
    """Load a fixed 32-byte AES key (base64 encoded in a file)."""
    with open(SESSION_KEY_FILE, "rb") as f:
        b64 = f.read().strip()
    key = base64.b64decode(b64)
    if len(key) != 32:
        raise ValueError(f"session_key must be 32 bytes after base64 decode, got {len(key)}")
    return key

def _load_rsa_public_key() -> RSAPublicKey:
    """Load RSA public key for OAEP wrapping."""
    with open(RSA_PUB_FILE, "rb") as f:
        data = f.read()
    pub = serialization.load_pem_public_key(data)
    if not isinstance(pub, RSAPublicKey):
        raise TypeError("rsa_pub.pem does not contain an RSA public key")
    return pub

def _load_ed25519_private_key() -> Ed25519PrivateKey:
    """Load Ed25519 private key for signing."""
    with open(SIGN_PRIV_FILE, "rb") as f:
        data = f.read()
    priv = serialization.load_pem_private_key(data, password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise TypeError("sign_priv.pem does not contain an Ed25519 private key")
    return priv

# Load keys at startup (fail fast if missing/bad)
SESSION_KEY = _load_session_key()
RSA_PUB = _load_rsa_public_key()
SIGN_PRIV = _load_ed25519_private_key()


producer = KafkaProducer(
    bootstrap_servers=[BROKER_ADDRESS],
    value_serializer=lambda x: json.dumps(x).encode('utf-8')
)

class Neighbour(BaseModel):
    vnf_id: str
    interface: str
    publickey: str

    class Config:
        extra = "forbid"

class VirtualLink(BaseModel):
    vl_id: str
    neighbours: List[Neighbour]

    class Config:
        extra = "forbid"


def _canonical_json_bytes(obj) -> bytes:
    """
    Canonical JSON bytes for consistent crypto cost across runs:
    - stable key ordering
    - no whitespace
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def emulate_crypto_cost(plain_obj, recipients_count: int) -> None:
    """
    Emulate cryptographic operations for cost evaluation only.
    The result is NOT sent over Kafka.
    """
    logging.info("Starting crypto emulation")

    # Encrypt full topology with symmetric key
    logging.info("Encrypting topology payload with AES-GCM")
    aesgcm = AESGCM(SESSION_KEY)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(
        nonce,
        _canonical_json_bytes(plain_obj),
        associated_data=None,
    )

    # Wrap session key once per recipient (n agents + Adjunct SA)
    logging.info(f"Wrapping session key for {recipients_count} recipients (RSA-OAEP)")
    for _ in range(recipients_count):
        RSA_PUB.encrypt(
            SESSION_KEY,
            asy_padding.OAEP(
                mgf=asy_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    # Sign encrypted metadata
    logging.info("Signing encrypted topology (Ed25519)")
    envelope_like = {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "recipients": recipients_count,
    }
    SIGN_PRIV.sign(_canonical_json_bytes(envelope_like))

    logging.info("Crypto emulation completed")


@app.post("/topology")
async def publish_topology(topology: List[VirtualLink]):
    """
    Receives service topology and publishes it to Kafka.
    Crypto operations are emulated for performance evaluation only.
    """
    try:
        logging.info("Topology received via HTTP")
        # Convert Pydantic models to plain dicts
        plain = [vl.dict() for vl in topology]

        # Compute number of distinct VNFs across all VLs
        logging.info("Computing number of distinct VNF_IDs (recipients)")
        vnf_ids = {n["vnf_id"] for vl in plain for n in vl["neighbours"]}
        n_agents = len(vnf_ids)
        recipients_count = n_agents + 1  # Adjunct SA

        logging.info(
            f"Topology analysis completed: n_agents={n_agents}, "
            f"recipients_count={recipients_count}"
        )

        # Emulate cryptographic workload
        if EMULATE_CRYPTO:
            emulate_crypto_cost(plain, recipients_count)
        else:
            logging.info("Crypto emulation disabled")
        
        logging.info("Publishing topology to Kafka")
        producer.send(TOPOLOGY_TOPIC, value=plain)
        producer.flush()
        logging.info("Topology published successfully.")
        return {"status": "ok", "message": "Topology published"}
    except Exception as e:
        logging.error(f"Kafka error: {e}")
        raise HTTPException(status_code=500, detail=f"Kafka error: {str(e)}")
