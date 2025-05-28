import serial
import hashlib
import time
import binascii
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os

# Method for computing the SHA256 hash of a message
# def compute_sha256(message: str) -> bytes:
#     sha = hashlib.sha256()
#     sha.update(message.encode('utf-8'))
#     return sha.digest()  

# This function sends a message to the ESP32 over serial
# It includes the SHA256 hash of the message for verification
# The message format is: "message::hash"
# The ESP32 should be programmed to read this format and verify the hash
# Appending the hash to the message allows the ESP32 to verify the integrity of the message
# The function also monutors the response from the ESP32 and prints to the console!
def send_and_monitor(port: str, baudrate: int, final_payload: str, read_lines: int = 100):
    print(f"Sending encrypted payload:\n{final_payload}")

    try:
        with serial.Serial(port, baudrate, timeout=1) as ser:
            time.sleep(2)  # gives the ESP32 time to reset
            ser.write(final_payload.encode('utf-8'))
            print("Message sent.\nListening for response...\n")

            lines_received = 0
            while lines_received < read_lines:
                line = ser.readline()
                if line:
                    print(f"> {line.decode('utf-8').strip()}")
                    lines_received += 1

    except serial.SerialException as e:
        print(f"Serial error: {e}")
        
def load_private_key(private_key_path: str):
    try:
        with open(private_key_path, 'rb') as private_key_file:
            private_key = serialization.load_pem_private_key(
                private_key_file.read(),
                password=None
            )
            print("Private key loaded successfully.")
            return private_key
    except FileNotFoundError:
        print(f"Private key file not found: {private_key_path}")
        return None
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None

def sign_message(private_key, message: str) -> str:
    if private_key is None:
        print("Private key is not loaded. Cannot sign the message.")
        return None
    # Convert the hashed message to bytes
    try:
        signature = private_key.sign(
        message.encode('utf-8'),
        padding.PKCS1v15(),  
        hashes.SHA256()
    )
        print("Message hash signed successfully.")
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        print(f"Error signing message: {e}")
        return None
    
def generate_aes_key_and_iv():
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)       # 128-bit IV (required for CBC mode)
    print("Generated AES key and IV.")
    return aes_key, iv    

def encrypt_payload_with_aes(payload: str, aes_key: bytes, iv: bytes) -> bytes:
    # Pad the plaintext to AES block size (128 bits)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(payload.encode('utf-8')) + padder.finalize()

    # Create AES-CBC cipher and encryptor
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_payload = encryptor.update(padded_data) + encryptor.finalize()

    print("Payload encrypted with AES.")
    return encrypted_payload

def load_public_key(public_key_path: str):
    try:
        with open(public_key_path, 'rb') as pub_key_file:
            public_key = serialization.load_pem_public_key(
                pub_key_file.read()
            )
            print("Public key loaded successfully.")
            return public_key
    except FileNotFoundError:
        print(f"Public key file not found: {public_key_path}")
        return None
    except Exception as e:
        print(f"Error loading public key: {e}")
        return None
    
def encrypt_aes_key_with_rsa(mcu_public_key, aes_key: bytes) -> bytes:
    try:
        encrypted_key = mcu_public_key.encrypt(
            aes_key,
            padding.PKCS1v15()
        )
        print("AES key encrypted with RSA.")
        return encrypted_key
    except Exception as e:
        print(f"Error encrypting AES key with RSA: {e}")
        return None
    
def create_final_encrypted_package(enc_aes_key: bytes, iv: bytes, enc_payload: bytes) -> str:
    # Base64-encode all components
    b64_key = base64.b64encode(enc_aes_key).decode('utf-8')
    b64_iv = base64.b64encode(iv).decode('utf-8')
    b64_payload = base64.b64encode(enc_payload).decode('utf-8')

    # Compose the final package
    final_message = f"{b64_key}::{b64_iv}::{b64_payload}"
    print("Final encrypted package created.")
    return final_message

if __name__ == "__main__":

    COM_PORT = "COM9"
    BAUD_RATE = 115200
    MESSAGE = "This is the new updated string!"
    private_key_path = "private_key.pem"

    private_key = load_private_key(private_key_path)
    # hashed_mssg = compute_sha256(MESSAGE)
    
    # Signing the message with the private key
    signature = sign_message(private_key, MESSAGE)
    
    aes_key, iv = generate_aes_key_and_iv()
    
    # Step: Create payload
    payload = f"{MESSAGE}::{signature}"

    # Step: Encrypt the payload using AES
    enc_payload = encrypt_payload_with_aes(payload, aes_key, iv)
    
    public_key_mcu = load_public_key("public_key_mcu.pem")
    
    enc_aes_key = encrypt_aes_key_with_rsa(public_key_mcu, aes_key)
    print(f"Encrypted AES key: {binascii.hexlify(enc_aes_key).decode('utf-8')}")
    
    final_message = create_final_encrypted_package(enc_aes_key, iv, enc_payload)
    
    # Step: Send the final encrypted package to the ESP32
    send_and_monitor(COM_PORT, BAUD_RATE, final_message, read_lines=100)