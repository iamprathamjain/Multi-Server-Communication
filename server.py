import os
import base64
import logging
from pathlib import Path
from datetime import datetime
from flask import Flask, request, abort, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from crypto_utils import (
    read_private_key_pem,
    read_public_key_pem,
    decrypt_data_with_aes,
    create_rsa_key_pair,
    write_private_key_pem,
    write_public_key_pem
)

# ---------- Colors ----------
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
RESET = "\033[0m"

# ---------- Configuration ----------
def init_config():
    """Initialize configuration settings"""
    config = {
        'BASE_DIR': Path(__file__).resolve().parent,
        'MAX_CONTENT_LENGTH': 10 * 1024 * 1024  # 10MB max upload size
    }
    config['KEY_DIR'] = config['BASE_DIR'] / "serverkeys"
    config['CLIENT_KEY_DIR'] = config['BASE_DIR'] / "clients_public_keys"
    config['LOG_DIR'] = config['BASE_DIR'] / "received_logs"
    config['SERVER_PRIV'] = config['KEY_DIR'] / "private.pem"
    config['SERVER_PUB'] = config['KEY_DIR'] / "public.pem"
    return config

def setup_logging(base_dir):
    """Configure logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(base_dir / 'decryption_server.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def create_directories(config):
    """Create folders"""
    config['KEY_DIR'].mkdir(exist_ok=True, mode=0o700)
    config['CLIENT_KEY_DIR'].mkdir(exist_ok=True, mode=0o700)
    config['LOG_DIR'].mkdir(exist_ok=True, mode=0o750)

def generate_keys_if_needed(priv_path, pub_path):
    """Generate server keys if missing"""
    if priv_path.exists() and pub_path.exists():
        print(f"{YELLOW}Server keys already exist. Skipping generation.{RESET}")
    else:
        priv, pub = create_rsa_key_pair()
        write_private_key_pem(priv_path, priv)
        write_public_key_pem(pub_path, pub)
        print(f"{GREEN}New server keys generated and stored in '{priv_path.parent}' directory.{RESET}")

    # Load or reuse pub key PEM for display
    if 'pub' in locals():
        public_key_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    else:
        with open(pub_path, 'r') as f:
            public_key_pem = f.read()

    print(f"\n{CYAN}Server public key PEM:\n{public_key_pem}{RESET}")
    print(f"{YELLOW}Share this public key with clients!{RESET}")
    print(f"\n{CYAN}Server private key path: {priv_path}{RESET}")
    print(f"{RED}Do NOT share the private key!{RESET}\n")

def load_private_key(key_path):
    """Load private key"""
    try:
        return read_private_key_pem(key_path)
    except Exception as e:
        raise RuntimeError(f"Failed to load private key: {e}")

def validate_request_data(data):
    """Validate request"""
    required_fields = ["encrypted_data", "encrypted_key", "iv"]
    if not all(field in data for field in required_fields):
        raise ValueError(f"Missing required fields: {', '.join(required_fields)}")
    return (data["encrypted_data"], data["encrypted_key"], data["iv"])

def process_decrypted_data(decrypted_data, log_dir):
    """Store decrypted data"""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
    filename = f"message_{timestamp}.data"
    dest = log_dir / filename
    dest.write_bytes(decrypted_data)
    dest.chmod(0o640)
    return filename

def decrypt_client_data(encrypted_data, encrypted_key, iv, server_private_key):
    """Hybrid decryption"""
    aes_key = server_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypt_data_with_aes(encrypted_data, aes_key, iv)

# ---------- Setup ----------
config = init_config()
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = config['MAX_CONTENT_LENGTH']
logger = setup_logging(config['BASE_DIR'])
create_directories(config)

# Check & generate server keys if needed, then display public key
generate_keys_if_needed(config['SERVER_PRIV'], config['SERVER_PUB'])

# Load server private key
try:
    server_private_key = load_private_key(config['SERVER_PRIV'])
    logger.info("Server private key loaded successfully")
except Exception as e:
    logger.error(f"Failed to load server private key: {e}")
    raise RuntimeError("Could not initialize server private key")

# ---------- Main Route ----------
@app.post('/decrypt')
def decrypt_data():
    """Decrypt endpoint"""
    if not request.is_json:
        abort(400, "Content-Type must be application/json")

    try:
        encrypted_data_b64, encrypted_key_b64, iv_b64 = validate_request_data(request.get_json())

        encrypted_data = base64.b64decode(encrypted_data_b64)
        encrypted_key = base64.b64decode(encrypted_key_b64)
        iv = base64.b64decode(iv_b64)

        decrypted_data = decrypt_client_data(encrypted_data, encrypted_key, iv, server_private_key)

        print(f"{GREEN}{decrypted_data}{RESET}")

        filename = process_decrypted_data(decrypted_data, config['LOG_DIR'])

        logger.info(f"Successfully processed data")

        return jsonify({
            "status": "success",
            "message": "Data decrypted and stored",
            "filename": filename
        }), 200

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        abort(400, str(e))
    except Exception as e:
        logger.error(f"Error processing data: {str(e)}")
        abort(400, f"Data processing failed: {str(e)}")

# ---------- Error Handlers ----------
@app.errorhandler(400)
def bad_request(error):
    return jsonify({"status": "error", "message": str(error.description)}), 400

@app.errorhandler(403)
def forbidden(error):
    return jsonify({"status": "error", "message": str(error.description)}), 403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1212, debug=False)
