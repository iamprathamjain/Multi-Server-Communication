from pathlib import Path
import os, base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ── RSA KEYPAIR HELPERS ────────────────────────────────────────────────────── #

def create_rsa_key_pair(key_bits: int = 2048):
    """Generate and return (private_key, public_key)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_bits,
        backend=default_backend(),
    )
    return private_key, private_key.public_key()

def write_private_key_pem(path: Path, private_key):
    """Save a private key in unencrypted PEM format."""
    path.parent.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
    path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

def write_public_key_pem(path: Path, public_key):
    """Save a public key in PEM format."""
    path.parent.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
    path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

def read_private_key_pem(path: Path):
    """Load an unencrypted private key from PEM."""
    return serialization.load_pem_private_key(
        path.read_bytes(),
        password=None,
        backend=default_backend(),
    )

def read_public_key_pem(path: Path):
    """Load a public key from PEM."""
    return serialization.load_pem_public_key(path.read_bytes(), backend=default_backend())

# ── AES FILE HELPERS ───────────────────────────────────────────────────────── #

def encrypt_file_with_aes(src: Path, dst: Path, aes_key: bytes, iv: bytes):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    with src.open("rb") as f_in, dst.open("wb") as f_out:
        while chunk := f_in.read(4096):
            f_out.write(encryptor.update(chunk))
        f_out.write(encryptor.finalize())

def decrypt_file_with_aes(src: Path, dst: Path, aes_key: bytes, iv: bytes):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    with src.open("rb") as f_in, dst.open("wb") as f_out:
        while chunk := f_in.read(4096):
            f_out.write(decryptor.update(chunk))
        f_out.write(decryptor.finalize())

def encrypt_data_with_aes(data: bytes, aes_key: bytes, iv: bytes) -> bytes:
    """Encrypt bytes data with AES key"""
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def decrypt_data_with_aes(encrypted_data: bytes, aes_key: bytes, iv: bytes) -> bytes:
    """Decrypt bytes data with AES key"""
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# ── HYBRID OPERATIONS ──────────────────────────────────────────────────────── #

def hybrid_encrypt(src: Path, dst: Path, recipient_pubkey):
    """
    1. Create random AES‑256 key and IV.
    2. Encrypt file with AES.
    3. Encrypt AES key with recipient's RSA public key.
    4. Return dict containing base64‑encoded AES key + IV.
    """
    aes_key = os.urandom(32)   # 256‑bit
    iv      = os.urandom(16)   # 128‑bit
    encrypt_file_with_aes(src, dst, aes_key, iv)

    encrypted_key = recipient_pubkey.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf      = asym_padding.MGF1(hashes.SHA256()),
            algorithm= hashes.SHA256(),
            label    = None,
        ),
    )
    return {
        "encrypted_key_b64": base64.b64encode(encrypted_key).decode(),
        "iv_b64"           : base64.b64encode(iv).decode(),
    }

def hybrid_decrypt(src: Path, dst: Path, encrypted_key_b64: str, iv_b64: str, recipient_privkey):
    """
    1. RSA‑decrypt the AES key.
    2. AES‑decrypt the file.
    """
    aes_key = recipient_privkey.decrypt(
        base64.b64decode(encrypted_key_b64),
        asym_padding.OAEP(
            mgf      = asym_padding.MGF1(hashes.SHA256()),
            algorithm= hashes.SHA256(),
            label    = None,
        ),
    )
    iv = base64.b64decode(iv_b64)
    decrypt_file_with_aes(src, dst, aes_key, iv)

def hybrid_encrypt_data(data, recipient_pubkey):
    """
    Encrypt text or Python objects using hybrid encryption (RSA + AES).
    
    Args:
        data: String or any Python object that can be serialized
        recipient_pubkey: RSA public key for the recipient
        
    Returns:
        dict containing encrypted data and keys in base64 format
    """
    import pickle
    
    # Convert input to bytes
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    else:
        data_bytes = pickle.dumps(data)
    
    # Generate random AES key and IV
    aes_key = os.urandom(32)   # 256‑bit
    iv = os.urandom(16)        # 128‑bit
    
    # Encrypt the data with AES
    encrypted_data = encrypt_data_with_aes(data_bytes, aes_key, iv)
    
    # Encrypt the AES key with RSA
    encrypted_key = recipient_pubkey.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    
    return {
        "encrypted_data_b64": base64.b64encode(encrypted_data).decode(),
        "encrypted_key_b64": base64.b64encode(encrypted_key).decode(),
        "iv_b64": base64.b64encode(iv).decode(),
    }

def hybrid_decrypt_data(encrypted_data_b64: str, encrypted_key_b64: str, iv_b64: str, 
                       recipient_privkey, is_text: bool = True):
    """
    Decrypt data that was encrypted using hybrid_encrypt_data.
    
    Args:
        encrypted_data_b64: Base64 encoded encrypted data
        encrypted_key_b64: Base64 encoded encrypted AES key
        iv_b64: Base64 encoded IV
        recipient_privkey: RSA private key for decryption
        is_text: If True, returns decrypted data as text, otherwise as Python object
        
    Returns:
        Decrypted text string or Python object
    """
    import pickle
    
    # Decrypt the AES key using RSA
    aes_key = recipient_privkey.decrypt(
        base64.b64decode(encrypted_key_b64),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    
    # Decrypt the data using AES
    decrypted_data = decrypt_data_with_aes(
        base64.b64decode(encrypted_data_b64),
        aes_key,
        base64.b64decode(iv_b64)
    )
    
    # Convert back to original format
    if is_text:
        return decrypted_data.decode('utf-8')
    else:
        return pickle.loads(decrypted_data)

# ── KEY MANAGEMENT ─────────────────────────────────────────────────────────── #

def delete_key_files(private_key_path: Path, public_key_path: Path):
    """Delete private and public key files if they exist."""
    try:
        if private_key_path.exists():
            private_key_path.unlink()
            print(f"Private key deleted: {private_key_path}")
        if public_key_path.exists():
            public_key_path.unlink()
            print(f"Public key deleted: {public_key_path}")
    except Exception as e:
        print(f"Error deleting keys: {e}")

def check_and_create_keys(private_key_path: Path, public_key_path: Path, key_bits: int = 2048):
    """
    Check if keys exist and create them only if they don't.
    Returns (private_key, public_key) tuple and a message about what happened.
    """
    # Check if both keys already exist
    if private_key_path.exists() and public_key_path.exists():
        try:
            # Try to load existing keys
            private_key = read_private_key_pem(private_key_path)
            public_key = read_public_key_pem(public_key_path)
            return (private_key, public_key), "Keys already exist and were loaded successfully."
        except Exception as e:
            return None, f"Existing keys are corrupted: {e}"
    
    # If either key is missing, create new pair
    elif not private_key_path.exists() or not public_key_path.exists():
        # Delete any existing single key to maintain pair consistency
        delete_key_files(private_key_path, public_key_path)
        
        # Create new key pair
        private_key, public_key = create_rsa_key_pair(key_bits)
        
        # Save the keys
        write_private_key_pem(private_key_path, private_key)
        write_public_key_pem(public_key_path, public_key)
        
        return (private_key, public_key), "New key pair created successfully."

# ── END‑TO‑END DEMO ────────────────────────────────────────────────────────── #

def main():
    # Create keys directory if it doesn't exist
    keys_dir = Path("serverkeys")
    keys_dir.mkdir(exist_ok=True)
    
    # 1️⃣ Key generation & storage
    priv, pub = create_rsa_key_pair()
    write_private_key_pem(keys_dir / "private.pem", priv)
    write_public_key_pem(keys_dir / "public.pem", pub)

    keys_dir = Path("clientkeys")
    keys_dir.mkdir(exist_ok=True)
    
    # 1️⃣ Key generation & storage
    priv, pub = create_rsa_key_pair()
    write_private_key_pem(keys_dir / "private.pem", priv)
    write_public_key_pem(keys_dir / "public.pem", pub)

    # 2️⃣ Encrypt a large log file
    # meta = hybrid_encrypt(
    #     src  = Path("my_logfile.csv"),
    #     dst  = Path("my_logfile.enc"),
    #     recipient_pubkey = pub,
    # )
    # print("RSA‑encrypted AES key:", meta["encrypted_key_b64"])
    # print("IV (base64):", meta["iv_b64"])

    # # 3️⃣ Decrypt back for verification
    # hybrid_decrypt(
    #     src  = Path("my_logfile.enc"),
    #     dst  = Path("my_logfile_decrypted.csv"),
    #     encrypted_key_b64 = meta["encrypted_key_b64"],
    #     iv_b64            = meta["iv_b64"],
    #     recipient_privkey = priv,
    # )
    # print("✅ Decryption successful.")

    # 4️⃣ Encrypt and decrypt text data
    data = "Hello, this is a secret message!"
    meta_data = hybrid_encrypt_data(data, pub)
    print("RSA‑encrypted AES key (data):", meta_data["encrypted_key_b64"])
    print("IV (base64, data):", meta_data["iv_b64"])

    decrypted_data = hybrid_decrypt_data(
        meta_data["encrypted_data_b64"],
        meta_data["encrypted_key_b64"],
        meta_data["iv_b64"],
        priv,
    )
    print("✅ Decryption successful (data):", decrypted_data)

if __name__ == "__main__":
    main()