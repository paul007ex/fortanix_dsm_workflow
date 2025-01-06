#!/usr/bin/python

from __future__ import print_function
import argparse
import base64
import sdkms
from sdkms.v1.models.cipher_mode import CipherMode
from sdkms.v1.models.object_type import ObjectType
from sdkms.v1.models.digest_algorithm import DigestAlgorithm
from termcolor import colored
"""
Secure Communication Using Fortanix DSM 

Description:
This script showcases a secure communication protocol between a sender (e.g., John) and a receiver (e.g., Priya) leveraging the Fortanix Data Security Manager (DSM). It demonstrates best practices in cryptography and key management, covering:

1. **Key Management in DSM**:
   - Creation and retrieval of cryptographic keys (AES and RSA) stored in the DSM.
   - Secure handling of symmetric (AES) and asymmetric (RSA) keys.

2. **Data Security**:
   - AES encryption for message confidentiality.
   - RSA encryption for securely transmitting the AES key.
   - Digital signatures for message authenticity and integrity.

3. **Protocol Workflow**:
   - Sender encrypts the message using AES and encrypts the AES key with RSA.
   - The message is signed using the sender's private RSA key.
   - Receiver decrypts the AES key using RSA and the message using AES.
   - Receiver verifies the signature using the sender's public RSA key.

Workflow Details:
1. **Initialization**:
   - Parse command-line arguments for DSM API configuration.
   - Authenticate with the DSM and initialize cryptographic clients.
   - Create or retrieve RSA and AES keys from DSM.

2. **Sender Workflow**:
   - Encrypt the plaintext message using AES.
   - Encrypt the AES key using the receiver's RSA public key.
   - Sign the message using the sender's RSA private key.

3. **Receiver Workflow**:
   - Decrypt the AES key using the receiver's RSA private key.
   - Decrypt the ciphertext using the AES key.
   - Verify the message's signature using the sender's RSA public key.

4. **Validation**:
   - Ensure the decrypted message matches the original plaintext.
   - Confirm the signature verification result.

Use Cases:
1. **Basic AES Workflow**:
   - Encrypt and decrypt a message using AES.

2. **Basic RSA Workflow**:
   - Encrypt a message using RSA and verify its integrity with a digital signature.

3. **Advanced AES-RSA Workflow**:
   - Combine AES for message encryption and RSA for key exchange.

Protocol Flow (Advanced AES-RSA Workflow):
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

Usage:
```bash
python secure_communication.py --api-key <Base64-Encoded-API-Key> --api-endpoint <DSM-Endpoint> --debug
```
Modules Used:
- `sdkms`: Fortanix SDK for DSM interactions.
- `argparse`: Parsing command-line arguments.
- `base64`: Encoding and decoding keys.
- `termcolor`: For color-coded logging.

"""

# Default configuration
DEFAULT_API_ENDPOINT = "https://apps.smartkey.io"
DEBUG = False

# Global variables
ca_certificate = None
api_instances = {}

# Utility Class for Logging
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

# Workflows
class Workflows:
    @staticmethod
    def basic_aes_encryption(message):
        """Basic AES Encryption Workflow."""
        Logger.log("Starting basic AES encryption workflow.")
        aes_key = CryptoManager.create_or_retrieve_key("Shared AES Key", ObjectType.AES, 256)
        encrypted_result = CryptoManager.encrypt(aes_key, message, ObjectType.AES, CipherMode.CBC)
        Logger.log(f"AES Encryption Result: {encrypted_result}")
        return encrypted_result

    @staticmethod
    def basic_rsa_workflow(message):
        """Basic RSA Encryption and Signature Workflow."""
        Logger.log("Starting basic RSA workflow.")
        sender_rsa_key = CryptoManager.create_or_retrieve_key("John's RSA Key", ObjectType.RSA, 2048)
        receiver_rsa_key = CryptoManager.create_or_retrieve_key("Priya's RSA Key", ObjectType.RSA, 2048)

        encrypted_result = CryptoManager.encrypt(receiver_rsa_key, message, ObjectType.RSA)
        Logger.log(f"RSA Encryption Result: {encrypted_result}")

        signed_data = CryptoManager.sign(sender_rsa_key, message)
        Logger.log(f"Signed Data: {signed_data}")

        decrypted_data = CryptoManager.decrypt(receiver_rsa_key, encrypted_result.cipher, ObjectType.RSA)
        Logger.log(f"Decrypted Data: {decrypted_data}")

        signature_valid = CryptoManager.verify(sender_rsa_key, decrypted_data, signed_data)
        Logger.log(f"Signature Verification Result: {signature_valid}")
        return decrypted_data, signature_valid

    @staticmethod
    def aes_rsa_combined_workflow(sender_rsa_key, receiver_rsa_key, shared_aes_key, plaintext):
        """Combined AES and RSA Workflow."""
        Logger.log("Starting AES-RSA combined workflow.")

        # Step 1: Encrypt plaintext using AES
        aes_encryption_result = CryptoManager.encrypt(
            key_id=shared_aes_key, 
            plaintext=plaintext, 
            object_type=ObjectType.AES, 
            mode=CipherMode.CBC
        )
        Logger.log(f"AES Encryption Result: {aes_encryption_result}")

        # Step 2: Encrypt AES key using receiver's RSA public key
        encrypted_aes_key_result = CryptoManager.encrypt(
            key_id=receiver_rsa_key, 
            plaintext=aes_encryption_result.kid,  # Encrypting AES key material
            object_type=ObjectType.RSA
        )
        Logger.log(f"Encrypted AES Key Result: {encrypted_aes_key_result}")

        # Step 3: Sign plaintext with sender's RSA private key
        signature = CryptoManager.sign(sender_rsa_key, plaintext)
        Logger.log(f"Generated Signature: {signature}")

        # Package results
        encrypted_data = {
            'ciphertext': aes_encryption_result.cipher,
            'iv': aes_encryption_result.iv,
            'encrypted_aes_key': encrypted_aes_key_result.cipher,
            'signature': signature
        }
        return encrypted_data

    @staticmethod
    def aes_rsa_receiver_workflow(receiver_private_key, sender_public_key, encrypted_data):
        """Receiver Workflow for AES-RSA Combined Encryption."""
        Logger.log("Starting AES-RSA receiver workflow.")

        # Step 1: Decrypt AES key using receiver's RSA private key
        decrypted_aes_key = CryptoManager.decrypt(
            key_id=receiver_private_key, 
            ciphertext=encrypted_data['encrypted_aes_key'], 
            object_type=ObjectType.RSA
        )
        Logger.log(f"Decrypted AES Key: {decrypted_aes_key}")

        # Step 2: Decrypt ciphertext using decrypted AES key
        plaintext_message = CryptoManager.decrypt(
            key_id=decrypted_aes_key, 
            ciphertext=encrypted_data['ciphertext'], 
            object_type=ObjectType.AES, 
            mode=CipherMode.CBC, 
            iv=encrypted_data['iv']
        )
        Logger.log(f"Decrypted Plaintext Message: {plaintext_message}")

        # Step 3: Verify digital signature
        is_signature_valid = CryptoManager.verify(
            key_id=sender_public_key, 
            message=plaintext_message, 
            signature=encrypted_data['signature']
        )
        Logger.log(f"Signature Verification Result: {is_signature_valid}")

        return plaintext_message, is_signature_valid

# Main Function
def main():
    """Main function demonstrating secure communication workflows."""
    DSMClient.initialize()

    # Create or retrieve keys
    sender_rsa_key = CryptoManager.create_or_retrieve_key("John's RSA Key", ObjectType.RSA, 2048)
    receiver_rsa_key = CryptoManager.create_or_retrieve_key("Priya's RSA Key", ObjectType.RSA, 2048)
    shared_aes_key = CryptoManager.create_or_retrieve_key("Shared AES Key", ObjectType.AES, 256)

    # Test message
    plaintext_message = "Hello Priya!"
    Logger.log(f"Plaintext Message: {plaintext_message}")

    # Sender Workflow
    encrypted_data = Workflows.aes_rsa_combined_workflow(
        sender_rsa_key, receiver_rsa_key, shared_aes_key, plaintext_message
    )
    Logger.log(f"Encrypted Data: {encrypted_data}")

    # Receiver Workflow
    decrypted_message, is_signature_valid = Workflows.aes_rsa_receiver_workflow(
        receiver_private_key=receiver_rsa_key,
        sender_public_key=sender_rsa_key,
        encrypted_data=encrypted_data
    )
    Logger.log(f"Decrypted Message: {decrypted_message}")
    Logger.log(f"Signature Verified: {is_signature_valid}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--api-key', required=True, help='Base64-encoded API key for DSM access')
    parser.add_argument('--api-endpoint', default=DEFAULT_API_ENDPOINT, help='Fortanix DSM API endpoint')
    parser.add_argument('--no-verify-ssl', action='store_false', dest='verify_ssl', help='Disable SSL verification')
    global cl_args
    cl_args = parser.parse_args()

    main()
