import os
import base64
import json
import requests
from pathlib import Path
from typing import Dict, Any
from crypto_utils import (
    create_rsa_key_pair,
    read_public_key_pem,
    hybrid_encrypt_data,
    write_private_key_pem,
    write_public_key_pem,
)
from cryptography.hazmat.primitives import serialization


def get_server_url(host: str = "localhost", port: int = 1212, use_https: bool = False) -> str:
    """Get the full server URL"""
    protocol = "https" if use_https else "http"
    return f"{protocol}://{host}:{port}/decrypt"


def get_server_public_key_path() -> Path:
    """Return the expected path for the server's public key"""
    return Path(__file__).resolve().parent / 'hostkeys' / 'public.pem'


def encrypt_message(message: str, server_public_key: Any) -> Dict[str, str]:
    """Encrypt the message using hybrid encryption"""
    encryption_result = hybrid_encrypt_data(message, server_public_key)
    return {
        "encrypted_data": encryption_result["encrypted_data_b64"],
        "encrypted_key": encryption_result["encrypted_key_b64"],
        "iv": encryption_result["iv_b64"]
    }


def send_encrypted_message(encrypted_payload: Dict[str, str], server_url: str) -> Dict[str, Any]:
    """Send encrypted message to the server"""
    try:
        response = requests.post(
            server_url,
            json=encrypted_payload,
            headers={"Content-Type": "application/json"},
            verify=True  # Change to False if using self-signed certs during dev
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to send message: {e}")


def process_decryption_request():
    """Main client loop: securely send encrypted messages to server"""
    try:
        key_path = get_server_public_key_path()

        # If missing: prompt user & wrap properly
        if not key_path.exists():
            print("Server public key not found in hostkeys directory.")
            os.makedirs(key_path.parent, exist_ok=True)

            server_public_value = input("Paste the server PUBLIC KEY PEM value:\n").strip()

            # ✅ If raw base64, wrap with PEM headers
            if not server_public_value.startswith("-----BEGIN"):
                server_public_value = (
                    "-----BEGIN PUBLIC KEY-----\n"
                    + server_public_value.strip()
                    + "\n-----END PUBLIC KEY-----"
                )

            with open(key_path, 'w') as f:
                f.write(server_public_value)

            print(f"Server public key saved to: {key_path}")

        # Load the server public key (safe, always valid PEM now)
        server_public_key = read_public_key_pem(key_path)

        # Server connection settings
        host = input("Enter server host (default: localhost): ").strip() or "localhost"
        port = int(input("Enter server port (default: 1212): ").strip() or "1212")
        use_https = input("Use HTTPS? (y/N): ").lower().startswith('y')

        server_url = get_server_url(host, port, use_https)

        while True:
            print("\nOptions:")
            print("1. Send message")
            print("2. Exit")

            choice = input("\nEnter your choice (1-2): ")

            if choice == "1":
                message = input("Enter your secret message: ")
                encrypted_payload = encrypt_message(message, server_public_key)
                response = send_encrypted_message(encrypted_payload, server_url)
                print("\nServer Response:")
                print(json.dumps(response, indent=2))

            elif choice == "2":
                break

            else:
                print("Invalid choice. Please try again.")

    except Exception as e:
        print(f"\nError: {e}")


# ====== Colors ======
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
RESET = "\033[0m"


if __name__ == "__main__":
    keys_dir = Path("clientkeys")
    keys_dir.mkdir(exist_ok=True)

    priv_key_path = keys_dir / "private.pem"
    pub_key_path = keys_dir / "public.pem"

    # Generate client key pair if missing
    if priv_key_path.exists() and pub_key_path.exists():
        print(f"{YELLOW}Keys already exist. Skipping generation.{RESET}")
    else:
        priv, pub = create_rsa_key_pair()
        write_private_key_pem(priv_key_path, priv)
        write_public_key_pem(pub_key_path, pub)
        print(f"{GREEN}New client keys generated and stored in 'clientkeys' directory.{RESET}")

    # Print client public key for sharing with server
    if 'pub' in locals():
        public_key_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    else:
        with open(pub_key_path, 'r') as f:
            public_key_pem = f.read()

    print(f"\n{CYAN}Public key path: {pub_key_path}{RESET}")
    print(f"{GREEN}Public key PEM:\n{public_key_pem}{RESET}")
    print(f"{YELLOW}Share the public key with the server!{RESET}")

    print(f"\n{CYAN}Private key path: {priv_key_path}{RESET}")
    print(f"{RED}Don't share the private key with anyone!{RESET}")

    process_decryption_request()
