from __future__ import print_function
import argparse
import base64
import os
import sdkms
import pprint
from sdkms.v1.models.cipher_mode import CipherMode
from sdkms.v1.models.object_type import ObjectType
from sdkms.v1.models.digest_algorithm import DigestAlgorithm
from termcolor import colored

#!/usr/bin/python
"""
Secure Communication Using Fortanix DSM

Description:
This script demonstrates a secure communication protocol between a sender (e.g., John) and a receiver (e.g., Priya) using the Fortanix Data Security Manager (DSM). It implements confidentiality, authenticity, and integrity through:
- Symmetric (AES) encryption for message confidentiality.
- Asymmetric (RSA) encryption for securely transmitting the AES key.
- Digital signatures for message authenticity and integrity.

Key Features:
1. **Key Management in DSM**:
   - All cryptographic keys are securely stored and managed in the Fortanix DSM.
   - RSA keys for asymmetric encryption/decryption.
   - AES keys for symmetric encryption/decryption.
2. **Data Security**:
   - AES encrypts the message for confidentiality.
   - RSA encrypts the AES key to securely transmit it.
   - The message is signed with the sender's private key for authenticity and integrity.
3. **Step-by-Step Protocol Workflow**:
   - Sender encrypts the message with an AES key.
   - The AES key is encrypted with the receiver's RSA public key.
   - The message is signed using the sender's RSA private key.
   - Receiver decrypts the AES key using their RSA private key.
   - Receiver decrypts the message using the AES key.
   - Receiver verifies the signature using the sender's RSA public key.

Protocol Workflow:
+------------------+               +-------------------+
|   Sender (John)  |               |  Receiver (Priya) |
+------------------+               +-------------------+
            |                                |
[Retrieve RSA Key]                  [Retrieve RSA Key]
[Retrieve AES Key]                               |
            v                                v
  [Encrypt Message]  ----------------->  [Decrypt AES Key]
  [Encrypt AES Key]                       [Decrypt Message]
  [Sign Message]                         [Verify Signature]
            |                                |
            v                                v
[["Hello Priya"](AES Key)](John's RSA Public Key)   [["Hello Priya"](AES Key)]
 + [Digest("Hello Priya")](Signed with John's RSA Private Key)]

Encapsulation Example:
Step 1: Message encrypted with AES key:
["Hello Priya"](AES Key)

Step 2: AES key encrypted with RSA:
[["Hello Priya"](AES Key)](John's RSA Public Key)

Step 3: Signed Message:
[[["Hello Priya"](AES Key)](John's RSA Public Key)] + [Digest("Hello Priya")](Signed with John's RSA Private Key)]

Workflow Details:
1. **Initialization**:
   - Parse arguments for DSM API configuration.
   - Authenticate and initialize DSM client.
   - Retrieve or create RSA and AES keys in DSM.

2. **Sender Workflow**:
   - Encrypt the plaintext message using an AES key.
   - Encrypt the AES key using the receiver's RSA public key.
   - Sign the message using the sender's RSA private key.
   - Transmit the ciphertext, encrypted AES key, and signature to the receiver.

3. **Receiver Workflow**:
   - Decrypt the AES key using the receiver's RSA private key.
   - Decrypt the ciphertext using the AES key.
   - Verify the message's signature using the sender's RSA public key.

4. **Validation**:
   - Ensure the decrypted message matches the original message.
   - Confirm the signature verification result.

Modules Used:
- `sdkms` for DSM interactions.
- `argparse` for command-line arguments.
- `base64` for API key handling.
- `termcolor` for color-coded logging.

Usage:
```bash
python secure_communication.py --api-key <Base64-Encoded-API-Key> --api-endpoint <DSM-Endpoint> --debug
```
"""

# Default configuration
DEFAULT_API_ENDPOINT = "https://apps.smartkey.io"
DEBUG = False

# Global variables
ca_certificate = None
api_instances = {}

# Utility functions
class Logger:
    @staticmethod
    def log(message, level="INFO"):
        color_map = {
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
        }
        print(f"[{level}] {colored(message, color_map.get(level.upper(), 'white'))}")

# DSM Client Initialization
class DSMClient:
    @staticmethod
    def initialize():
        """Initialize the Fortanix DSM client."""
        global api_instances
        api_key = base64.b64decode(cl_args.api_key).decode('ascii')
        username, password = api_key.split(':')

        config = sdkms.v1.configuration.Configuration()
        config.username = username
        config.password = password
        config.verify_ssl = cl_args.verify_ssl
        config.host = cl_args.api_endpoint
        
        if ca_certificate:
            config.ssl_ca_cert = ca_certificate

        client = sdkms.v1.ApiClient(configuration=config)
        auth_instance = sdkms.v1.AuthenticationApi(api_client=client)
        auth = auth_instance.authorize()
        
        config.api_key['Authorization'] = auth.access_token
        config.api_key_prefix['Authorization'] = 'Bearer'

        api_instances = {
            'auth': auth_instance,
            'crypto': sdkms.v1.EncryptionAndDecryptionApi(api_client=client),
            'signverify': sdkms.v1.SignAndVerifyApi(api_client=client),
            'digest': sdkms.v1.DigestApi(api_client=client),
            'sobjects': sdkms.v1.SecurityObjectsApi(api_client=client)
        }
        Logger.log("DSM client initialized successfully.")

    @staticmethod
    def get_instance(name):
        return api_instances[name]

# CryptoManager
class CryptoManager:
    @staticmethod
    def create_or_retrieve_key(name, key_type, size):
        """Create or retrieve a key from DSM."""
        Logger.log(f"Checking if key '{name}' exists.")
        keys = DSMClient.get_instance('sobjects').get_security_objects()
        for key in keys:
            if key.name == name:
                Logger.log(f"Key '{name}' found with ID: {key.kid}")
                return key.kid
        
        Logger.log(f"Creating new key: {name}")
        request = sdkms.v1.SobjectRequest(
            name=name, key_size=size, obj_type=key_type
        )
        key_id = DSMClient.get_instance('sobjects').generate_security_object(request).kid
        Logger.log(f"Key '{name}' created with ID: {key_id}")
        return key_id

    @staticmethod
    def encrypt(key_id, plaintext, object_type, mode=None, iv=None):
        """Encrypt plaintext using DSM."""
        Logger.log("Encrypting data.")
        encrypt_request = sdkms.v1.EncryptRequest(
            alg=object_type, plain=bytearray(plaintext, 'utf-8'), mode=mode, iv=iv
        )
        result = DSMClient.get_instance('crypto').encrypt(key_id, encrypt_request)
        Logger.log(f"Encryption successful. Ciphertext: {result.cipher}")
        return result

    @staticmethod
    def decrypt(key_id, ciphertext, object_type, mode=None, iv=None):
        """Decrypt ciphertext using DSM."""
        Logger.log("Decrypting data.")
        decrypt_request = sdkms.v1.DecryptRequest(
            alg=object_type, cipher=ciphertext, mode=mode, iv=iv
        )
        result = DSMClient.get_instance('crypto').decrypt(key_id, decrypt_request)
        Logger.log(f"Decryption successful. Plaintext: {result.plain.decode('utf-8')}")
        return result.plain.decode('utf-8')

    @staticmethod
    def sign(key_id, message):
        """Sign a message using DSM."""
        Logger.log("Signing data.")
        digest_request = sdkms.v1.DigestRequest(
            alg=DigestAlgorithm.SHA256, data=bytearray(message, 'utf-8')
        )
        digest = DSMClient.get_instance('digest').compute_digest(digest_request).digest

        sign_request = sdkms.v1.SignRequest(hash=digest, hash_alg=DigestAlgorithm.SHA256)
        result = DSMClient.get_instance('signverify').sign(key_id, sign_request)
        Logger.log(f"Signature generated: {result.signature}")
        return result.signature

    @staticmethod
    def verify(key_id, message, signature):
        """Verify a signature using DSM."""
        Logger.log("Verifying signature.")
        digest_request = sdkms.v1.DigestRequest(
            alg=DigestAlgorithm.SHA256, data=bytearray(message, 'utf-8')
        )
        digest = DSMClient.get_instance('digest').compute_digest(digest_request).digest

        verify_request = sdkms.v1.VerifyRequest(
            hash=digest, signature=signature, hash_alg=DigestAlgorithm.SHA256
        )
        result = DSMClient.get_instance('signverify').verify(key_id, verify_request)
        Logger.log(f"Signature verification result: {result.result}")
        return result.result

# Workflow
class SecureWorkflow:
    @staticmethod
    def sender_workflow(sender_private_key, receiver_public_key, plaintext, aes_key_id):
        """Sender encrypts and signs a message."""
        Logger.log("Starting sender workflow.")
        Logger.log("Starting aes encryption...")
        aes_encryption_result = CryptoManager.encrypt(
            aes_key_id, plaintext, ObjectType.AES, mode=CipherMode.CBC
        )
        Logger.log(f"aes_encryption_result: {aes_encryption_result}")
        encrypted_aes_key = CryptoManager.encrypt(
            receiver_public_key, aes_encryption_result.kid, ObjectType.RSA
        )

        signature = CryptoManager.sign(sender_private_key, plaintext)
        return {
            'ciphertext': aes_encryption_result.cipher,
            'iv': aes_encryption_result.iv,
            'encrypted_aes_key': encrypted_aes_key.cipher,
            'signature': signature
        }

    @staticmethod
    def receiver_workflow(receiver_private_key, sender_public_key, data):
        """Receiver decrypts and verifies a message."""
        Logger.log("Starting receiver workflow.")
        decrypted_aes_key = CryptoManager.decrypt(
            receiver_private_key, data['encrypted_aes_key'], ObjectType.RSA
        )
        
        plaintext = CryptoManager.decrypt(
            decrypted_aes_key, data['ciphertext'], ObjectType.AES, mode=CipherMode.CBC, iv=data['iv']
        )
        
        is_verified = CryptoManager.verify(sender_public_key, plaintext, data['signature'])
        return plaintext, is_verified

# Main Function
def main():
    """Demonstrates the secure communication workflow."""
    DSMClient.initialize()

    sender_key = CryptoManager.create_or_retrieve_key("Sender RSA Key", ObjectType.RSA, 2048)
    receiver_key = CryptoManager.create_or_retrieve_key("Receiver RSA Key", ObjectType.RSA, 2048)
    aes_key = CryptoManager.create_or_retrieve_key("AES Key", ObjectType.AES, 256)

    plaintext = "Hello Priya!"
    Logger.log(f"Plaintext Message: {plaintext}")

    # Sender workflow
    encrypted_data = SecureWorkflow.sender_workflow(sender_key, receiver_key, plaintext, aes_key)
    Logger.log(f"Encrypted Data: {encrypted_data}")

    # Receiver workflow
    decrypted_message, is_verified = SecureWorkflow.receiver_workflow(receiver_key, sender_key, encrypted_data)
    Logger.log(f"Decrypted Message: {decrypted_message}")
    Logger.log(f"Signature Verified: {is_verified}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--api-key', required=True, help='Base64-encoded API key for DSM access')
    parser.add_argument('--api-endpoint', default=DEFAULT_API_ENDPOINT, help='Fortanix DSM API endpoint')
    parser.add_argument('--no-verify-ssl', action='store_false', dest='verify_ssl', help='Disable SSL verification')
    global cl_args
    cl_args = parser.parse_args()

    main()
