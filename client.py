import os
import base64
import json
import shutil
import requests
from pathlib import Path
from typing import Dict, Any, Tuple
from crypto_utils import (
    read_public_key_pem,
    hybrid_encrypt_data,
)

def get_server_url(host: str = "localhost", port: int = 1212, use_https: bool = False) -> str:
    """Get the full server URL"""
    protocol = "https" if use_https else "http"
    return f"{protocol}://{host}:{port}/decrypt"

def get_server_public_key() -> Path:
    """Get the path to the server's public key"""
    return Path(__file__).resolve().parent / 'serverkeys' / 'public.pem'
    try:
        key_path = key_dir / "server_public.pem"
        if key_path.exists():
            key_path.unlink()
            print("Server public key deleted successfully")
        else:
            print("No server public key found")
    except Exception as e:
        raise RuntimeError(f"Failed to delete server public key: {e}")

def load_server_public_key(key_dir: Path) -> Any:
    """Load the server's public key"""
    try:
        key_path = key_dir / "server_public.pem"
        if not key_path.exists():
            raise FileNotFoundError("Server public key not found. Please save it first.")
        return read_public_key_pem(key_path)
    except Exception as e:
        raise RuntimeError(f"Failed to load server public key: {e}")

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
            verify=True  # Set to False if using self-signed certificates
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to send message: {e}")

def process_decryption_request():
    """Process the decryption request to the server"""
    try:
        # Get the server's public key path
        key_path = get_server_public_key()
        if not key_path.exists():
            print("Error: Server public key not found in serverkeys directory!")
            return
        
        # Load the server public key
        server_public_key = read_public_key_pem(key_path)
        
        # Get server connection details
        host = input("Enter server host (default: localhost): ").strip() or "localhost"
        port = int(input("Enter server port (default: 1212): ").strip() or "1212")
        use_https = input("Use HTTPS? (y/N): ").lower().startswith('y')

        # Create directory if it doesn't exist
        if not os.path.exists('serverkeys'):
            os.makedirs('serverkeys')

        # Ask for server public value path
        server_public_value_path = input("Enter server public value: ").strip()

        # Save the value to a file
        with open('serverkeys/server_public_value.pem', 'w') as f:
            f.write(server_public_value_path)

        print(f"Server public value saved to: serverkeys/server_public_value.pem")

        # Get the server URL
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

if __name__ == "__main__":
    process_decryption_request()



