import os
import base64
import logging
from pathlib import Path
from datetime import datetime
from flask import Flask, request, abort, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from crypto_utils import (
    read_private_key_pem,
    read_public_key_pem,
    decrypt_data_with_aes,
)

# ---------- Configuration ----------
def init_config():
    """Initialize configuration settings"""
    config = {
        'BASE_DIR': Path(__file__).resolve().parent,
        'MAX_CONTENT_LENGTH': 10 * 1024 * 1024  # 10MB max upload size
    }
    config['KEY_DIR'] = config['BASE_DIR'] / "serverkeys"
    config['CLIENT_KEY_DIR'] = config['KEY_DIR'] / "clients"  # Client public keys stored here
    config['LOG_DIR'] = config['BASE_DIR'] / "received_logs"
    config['SERVER_PRIV'] = config['KEY_DIR'] / "private.pem"
    return config

def setup_logging(base_dir):
    """Configure logging settings"""
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
    """Create necessary directories with appropriate permissions"""
    config['KEY_DIR'].mkdir(exist_ok=True, mode=0o700)
    config['CLIENT_KEY_DIR'].mkdir(exist_ok=True, mode=0o700)
    config['LOG_DIR'].mkdir(exist_ok=True, mode=0o750)

def load_private_key(key_path):
    """Load private key from file"""
    try:
        return read_private_key_pem(key_path)
    except Exception as e:
        raise RuntimeError(f"Failed to load private key: {e}")

def load_public_key(key_path):
    """Load public key from file"""
    try:
        return read_public_key_pem(key_path)
    except Exception as e:
        raise RuntimeError(f"Failed to load public key: {e}")

def validate_request_data(data):
    """Validate the incoming request data"""
    required_fields = ["encrypted_data", "encrypted_key", "iv"]
    if not all(field in data for field in required_fields):
        raise ValueError(f"Missing required fields: {', '.join(required_fields)}")
    
    return (data["encrypted_data"], data["encrypted_key"], data["iv"])

def process_decrypted_data(decrypted_data, log_dir):
    """Store the decrypted data with timestamp"""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
    filename = f"message_{timestamp}.data"
    dest = log_dir / filename
    dest.write_bytes(decrypted_data)
    dest.chmod(0o640)
    return filename

def decrypt_client_data(encrypted_data, encrypted_key, iv, server_private_key):
    """Decrypt client data using hybrid encryption"""
    # First decrypt the AES key using server's private key
    aes_key = server_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Then decrypt the actual data using the AES key
    return decrypt_data_with_aes(encrypted_data, aes_key, iv)

# ---------- Setup ----------
config = init_config()
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = config['MAX_CONTENT_LENGTH']
logger = setup_logging(config['BASE_DIR'])
create_directories(config)

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
    """
    Endpoint to receive and decrypt client data
    Expected JSON format:
    {
        "encrypted_data": "base64_encoded_encrypted_data",
        "encrypted_key": "base64_encoded_encrypted_aes_key",
        "iv": "base64_encoded_iv"
    }
    """
    if not request.is_json:
        abort(400, "Content-Type must be application/json")
    
    try:
        # Validate and extract request data
        encrypted_data_b64, encrypted_key_b64, iv_b64 = validate_request_data(request.get_json())
        
        # Decode the base64 data
        encrypted_data = base64.b64decode(encrypted_data_b64)
        encrypted_key = base64.b64decode(encrypted_key_b64)
        iv = base64.b64decode(iv_b64)
        
        # Decrypt the data
        decrypted_data = decrypt_client_data(encrypted_data, encrypted_key, iv, server_private_key)

        print(decrypted_data)
        
        # Store the decrypted data
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