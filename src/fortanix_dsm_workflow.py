#!/usr/bin/python
"""
Fortanix Secure Communication Script
====================================

Description:
    This script demonstrates secure communication workflows using Fortanix DSM. 
    It supports AES encryption, RSA encryption, and a combined AES-RSA workflow to ensure 
    confidentiality, integrity, and authenticity of messages.

Usage:
    python fortanix_dsm_workflow.py --api-key <API_KEY> --workflow <aes|rsa|combined> --message <message>

Author:
    Paul Volosen
    paul007ex@mgmail.com

Version:
    1.0.0

Date:
    2026-01-18

License:
    This script is licensed under the MIT License.
    See the LICENSE file for details.

Dependencies:
    - argparse (Standard Library)
    - Fortanix DSM SDK (Install via pip: `pip install fortanix-dsm-sdk`)
    - Python 3.8 or higher

Notes:
    - Ensure that Fortanix DSM is properly configured with API access.
    - Verify that the required keys are created in DSM prior to execution.

Key Features:
1. Key Management in DSM:
   - Creation and retrieval of cryptographic keys (AES and RSA) securely stored in the DSM.
   - Secure handling of symmetric (AES) and asymmetric (RSA) keys.

2. Data Security:
   - AES encryption for message confidentiality.
   - RSA encryption for securely transmitting the AES key.
   - Digital signatures for message authenticity and integrity.

3. Protocol Workflow:
   - Sender encrypts the message using AES and encrypts the AES key with RSA.
   - The message is signed using the sender's private RSA key.
   - Receiver decrypts the AES key using RSA and the message using AES.
   - Receiver verifies the signature using the sender's public RSA key.

Workflow Details:
1. Initialization:
   - Parse command-line arguments for DSM API configuration.
   - Authenticate with the DSM and initialize cryptographic clients.
   - Create or retrieve RSA and AES keys from DSM.

2. Sender Workflow:
   - Encrypt the plaintext message using AES.
   - Encrypt the AES key using the receiver's RSA public key.
   - Sign the message using the sender's RSA private key.

3. Receiver Workflow:
   - Decrypt the AES key using the receiver's RSA private key.
   - Decrypt the ciphertext using the AES key.
   - Verify the message's signature using the sender's RSA public key.

4. Validation:
   - Ensure the decrypted message matches the original plaintext.
   - Confirm the signature verification result.

Use Cases:
1. Basic AES Workflow:
   - Encrypt and decrypt a message using AES.

2. Basic RSA Workflow:
   - Encrypt a message using RSA and verify its integrity with a digital signature.

3. Advanced AES-RSA Workflow:
   - Combine AES for message encryption and RSA for key exchange.

Protocol Flow (Example: Advanced AES-RSA Workflow):
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
["Hello Priya"(AES Key)](John's RSA Public Key)   ["Hello Priya"(AES Key)]
 + [Digest("Hello Priya")](Signed with John's RSA Private Key)

Encapsulation Example:
Step 1: Message encrypted with AES key:
["Hello Priya"(AES Key)]

Step 2: AES key encrypted with RSA:
[["Hello Priya"(AES Key)](John's RSA Public Key)]

Step 3: Signed Message:
[[["Hello Priya"(AES Key)](John's RSA Public Key)] + [Digest("Hello Priya")](Signed with John's RSA Private Key)]

Usage:
```bash
python fortanix_dsm_workflow.py --api-key <Base64-Encoded-API-Key> --api-endpoint <DSM-Endpoint> --workflow <rsa|aes|combined> --debug
```

Modules Used:
- `sdkms`: Fortanix SDK for DSM interactions.
- `argparse`: Parsing command-line arguments.
- `base64`: Encoding and decoding keys.
- `termcolor`: For color-coded logging.
"""

from __future__ import print_function
import os
import argparse
import base64
import sdkms
from sdkms.v1.models.cipher_mode import CipherMode
from sdkms.v1.models.object_type import ObjectType
from sdkms.v1.models.digest_algorithm import DigestAlgorithm
from termcolor import colored

# Default configuration

DEFAULT_API_ENDPOINT = "https://apps.smartkey.io"
  

DEBUG = False

# Global variables

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

class DSMClient:
    """
    DSMClient
    ==========

    This class provides utilities for interacting with the Fortanix DSM API. It includes methods
    to initialize the DSM client and retrieve specific API instances for cryptographic operations.

    Methods:
        - initialize: Authenticates with the DSM and sets up API instances.
        - get_instance: Retrieves the API instance for a given functionality (e.g., encryption, signing).

    Dependencies:
        - Fortanix DSM SDK (sdkms)
        - Logger: For detailed logging.

    """

    @staticmethod
    def initialize():
        """
        Initialize the Fortanix DSM Client
        ---------------------------------

        This method authenticates with the Fortanix DSM using the API key provided via command-line arguments.
        It sets up API instances for cryptographic operations such as encryption, signing, and key management.

        Logs:
            - Successful initialization.
            - Configuration details in a structured format.
            - Errors during configuration or authentication.
        """
        Logger.log("[Step 1] Initializing the DSM client.")

        global api_instances
        try:
            # Step 1: Decode the API key
            api_key = base64.b64decode(cl_args.api_key).decode('ascii')
            username, password = api_key.split(':')
            Logger.log("[Step 2] API key decoded successfully.")

            # Step 2: Configure DSM client
            config = sdkms.v1.configuration.Configuration()
            config.username = username
            config.password = password
            config.host = cl_args.api_endpoint

            # Pretty print the configuration
            config_attributes = vars(config)
            formatted_config = "\n".join(
                f"{key}: {value}" for key, value in config_attributes.items() if value is not None
            )
            Logger.log(f"[Step 3] DSM client configured with the following settings:\n{formatted_config}")

            # Step 3: Authenticate with DSM
            client = sdkms.v1.ApiClient(configuration=config)
            auth_instance = sdkms.v1.AuthenticationApi(api_client=client)
            auth = auth_instance.authorize()

            # Step 4: Store the access token
            config.api_key['Authorization'] = auth.access_token
            config.api_key_prefix['Authorization'] = 'Bearer'
            Logger.log("[Step 4] Authentication successful. Access token retrieved.")

            # Step 5: Initialize API instances
            api_instances = {
                'auth': auth_instance,
                'crypto': sdkms.v1.EncryptionAndDecryptionApi(api_client=client),
                'signverify': sdkms.v1.SignAndVerifyApi(api_client=client),
                'digest': sdkms.v1.DigestApi(api_client=client),
                'sobjects': sdkms.v1.SecurityObjectsApi(api_client=client)
            }
            Logger.log("[Step 5] DSM API instances initialized successfully.")

        except Exception as e:
            Logger.log(f"[Error] Failed to initialize DSM client: {e}", level="ERROR")
            raise

    
    @staticmethod
    def get_instance(name):
        """
        Get DSM API Instance
        --------------------

        Retrieves the API instance for a given functionality (e.g., encryption, signing).

        Parameters:
            name (str): The name of the API instance to retrieve. Valid options include:
                - 'auth': Authentication API
                - 'crypto': Encryption and Decryption API
                - 'signverify': Signing and Verification API
                - 'digest': Digest API
                - 'sobjects': Security Objects API

        Returns:
            sdkms.v1.<API_Instance>: The requested API instance.

        Logs:
            - Retrieval of the specified API instance.
            - Errors if the instance is not found.

        Raises:
            KeyError: If the requested API instance name is invalid or not initialized.
        """
        Logger.log(f"Retrieving API instance for: {name}")
        if name not in api_instances:
            Logger.log(f"[Error] API instance '{name}' not found.", level="ERROR")
            raise KeyError(f"API instance '{name}' is not initialized.")

        return api_instances[name]


# CryptoManager
class CryptoManager:
    """
    CryptoManager
    ==============

    This class provides utility functions to manage cryptographic operations 
    using the Fortanix DSM. It includes methods for key management, encryption, 
    decryption, signing, and signature verification.

    Methods:
        - create_or_retrieve_key: Creates or retrieves cryptographic keys.
        - encrypt: Encrypts plaintext using the DSM.
        - decrypt: Decrypts ciphertext using the DSM.
        - sign: Signs data using the DSM.
        - verify: Verifies a signature using the DSM.

    Dependencies:
        - Fortanix DSM SDK (sdkms)
        - Logger (custom logging utility)

    """

    @staticmethod
    def create_or_retrieve_key(name, key_type, size):
        """
        Create or Retrieve a Cryptographic Key
        --------------------------------------

        This method checks if a key with the given name exists in the DSM. If found,
        it retrieves the key. Otherwise, it creates a new key with the specified type
        and size.

        Parameters:
            name (str): Name of the key to retrieve or create.
            key_type (str): Type of the key (e.g., ObjectType.AES or ObjectType.RSA).
            size (int): Key size (e.g., 256 for AES, 2048 for RSA).

        Returns:
            str: The key ID of the retrieved or newly created key.

        Logs:
            - Checks for existing keys.
            - Logs if the key is found or created.
        """
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
        """
        Encrypt Data
        ------------

        Encrypts plaintext using a specified cryptographic key stored in the DSM.

        Parameters:
            key_id (str): The ID of the key to use for encryption.
            plaintext (str): The data to encrypt.
            object_type (str): The type of encryption algorithm (e.g., ObjectType.AES).
            mode (str, optional): The encryption mode (e.g., CipherMode.CBC).
            iv (bytes, optional): The initialization vector (IV) for the encryption.

        Returns:
            sdkms.v1.EncryptResponse: The encryption result, including ciphertext and metadata.

        Logs:
            - Encryption start.
            - Encryption success with ciphertext details.
        """
        Logger.log(f"Encrypting the following plaintext: {plaintext}.")
        encrypt_request = sdkms.v1.EncryptRequest(
            alg=object_type, plain=bytearray(plaintext, 'utf-8'), mode=mode, iv=iv #iv is important for AES encryption
        )
        result = DSMClient.get_instance('crypto').encrypt(key_id, encrypt_request)
        Logger.log(f"Encryption successful. Ciphertext: {result.cipher}")
        return result

    @staticmethod
    def decrypt(key_id, ciphertext, object_type, mode=None, iv=None):
        """
        Decrypt Data
        ------------

        Decrypts ciphertext using a specified cryptographic key stored in the DSM.

        Parameters:
            key_id (str): The ID of the key to use for decryption.
            ciphertext (bytes): The encrypted data to decrypt.
            object_type (str): The type of encryption algorithm (e.g., ObjectType.AES).
            mode (str, optional): The decryption mode (e.g., CipherMode.CBC).
            iv (bytes, optional): The initialization vector (IV) used during encryption.

        Returns:
            str: The decrypted plaintext data.

        Logs:
            - Decryption start.
            - Decryption success with plaintext details.
        """
        Logger.log("Decrypting data.")
        decrypt_request = sdkms.v1.DecryptRequest(
            alg=object_type, cipher=ciphertext, mode=mode, iv=iv
        )
        result = DSMClient.get_instance('crypto').decrypt(key_id, decrypt_request)
        Logger.log(f"Decryption successful. Plaintext: {result.plain.decode('utf-8')}")
        return result.plain.decode('utf-8')

    @staticmethod
    def sign(key_id, message):
        """
        Sign Data
        ---------

        Generates a digital signature for the given message using a specified key.

        Parameters:
            key_id (str): The ID of the key to use for signing.
            message (str): The data to sign.

        Returns:
            bytes: The generated digital signature.

        Logs:
            - Signing start.
            - Signing success with signature details.
        """
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
        """
        Verify a Signature
        ------------------

        Verifies the digital signature of a message using a specified key.

        Parameters:
            key_id (str): The ID of the key to use for verification.
            message (str): The original message.
            signature (bytes): The digital signature to verify.

        Returns:
            bool: True if the signature is valid; otherwise, False.

        Logs:
            - Verification start.
            - Verification result.
        """
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
    """
    Workflows
    ==========

    This class provides pre-defined cryptographic workflows for secure communication
    using the Fortanix DSM. The workflows utilize AES, RSA, or a combination of both
    for encryption, decryption, signing, and signature verification.

    Methods:
        - basic_aes_encryption: Simple AES encryption and decryption workflow.
        - basic_rsa_workflow: RSA-based encryption and signature verification workflow.
        - aes_rsa_combined_workflow: Hybrid workflow combining AES and RSA operations.

    Dependencies:
        - CryptoManager: For cryptographic operations.
        - Logger: For detailed logging.

    """

    @staticmethod
    def basic_aes_encryption(message):
        """
        Basic AES Encryption Workflow
        -----------------------------

        Demonstrates a simple AES encryption and decryption workflow.

        Steps:
        1. Retrieve or create a shared AES key from the DSM.
        2. Encrypt the plaintext message using AES in CBC mode.
        3. Decrypt the ciphertext using the same AES key and the generated IV.

        Parameters:
            message (str): The plaintext message to be encrypted and decrypted.

        Returns:
            None

        Logs:
            - Logs each step of the AES workflow.
        """
        Logger.log("[Step 1] Starting Basic AES Encryption Workflow.")

        # Step 1: Retrieve or create the AES key
        Logger.log("[Step 2] Retrieving or creating the shared AES key.")
        aes_key = CryptoManager.create_or_retrieve_key("Shared AES Key", ObjectType.AES, 256)
        Logger.log(f"[Step 3] Shared AES Key ID: {aes_key}")

        # Step 2: Encrypt the message using AES in CBC mode
        Logger.log("[Step 4] Encrypting the plaintext message using AES in CBC mode.")
        encrypted_result = CryptoManager.encrypt(
            key_id=aes_key,
            plaintext=message,
            object_type=ObjectType.AES,
            mode=CipherMode.CBC
        )
        Logger.log(f"[Step 5] AES Encryption Result: Ciphertext: {encrypted_result.cipher}, IV: {encrypted_result.iv}")

        # Step 3: Decrypt the ciphertext using the AES key and IV
        Logger.log("[Step 6] Decrypting the ciphertext back to plaintext.")
        decrypt_result = CryptoManager.decrypt(
            key_id=aes_key,
            ciphertext=encrypted_result.cipher,
            object_type=ObjectType.AES,
            mode=CipherMode.CBC,
            iv=encrypted_result.iv
        )
        Logger.log(f"[Step 7] AES Decryption Result: Plaintext: {decrypt_result}")

        Logger.log("[Complete] Basic AES Encryption Workflow completed successfully.")

    @staticmethod
    def basic_rsa_workflow(message):
        """
        Basic RSA Encryption and Signature Workflow
        ------------------------------------------

        Demonstrates a complete RSA-based cryptographic workflow.

        Steps:
        1. Retrieve or create the sender's RSA key.
        2. Retrieve or create the receiver's RSA key.
        3. Encrypt the plaintext message with the receiver's public RSA key.
        4. Sign the plaintext message with the sender's private RSA key.
        5. Decrypt the ciphertext using the receiver's private RSA key.
        6. Verify the signature using the sender's public RSA key.

        Parameters:
            message (str): The plaintext message to be encrypted and signed.

        Returns:
            tuple:
                decrypted_data (str): The decrypted message.
                signature_valid (bool): Whether the signature verification succeeded.

        Logs:
            - Logs each step of the RSA workflow.
        """
        Logger.log("[Step 1] Starting Basic RSA Workflow.")

        # Step 1: Retrieve or create the sender's RSA key
        sender_rsa_key = CryptoManager.create_or_retrieve_key("John's RSA Key", ObjectType.RSA, 2048)
        Logger.log("[Step 2] Sender's RSA Key created or retrieved.")

        # Step 2: Retrieve or create the receiver's RSA key
        receiver_rsa_key = CryptoManager.create_or_retrieve_key("Priya's RSA Key", ObjectType.RSA, 2048)
        Logger.log("[Step 3] Receiver's RSA Key created or retrieved.")

        # Step 3: Encrypt the plaintext message with the receiver's public RSA key
        encrypted_result = CryptoManager.encrypt(receiver_rsa_key, message, ObjectType.RSA)
        Logger.log(f"[Step 4] RSA Encryption Result: Cipher={encrypted_result.cipher}")

        # Step 4: Sign the plaintext message with the sender's private RSA key
        signed_data = CryptoManager.sign(sender_rsa_key, message)
        Logger.log(f"[Step 5] Signed Data: {signed_data}")

        # Step 5: Decrypt the ciphertext using the receiver's private RSA key
        decrypted_data = CryptoManager.decrypt(receiver_rsa_key, encrypted_result.cipher, ObjectType.RSA)
        Logger.log(f"[Step 6] Decrypted Data: {decrypted_data}")

        # Step 6: Verify the signature using the sender's public RSA key
        signature_valid = CryptoManager.verify(sender_rsa_key, decrypted_data, signed_data)
        Logger.log(f"[Step 7] Signature Verification Result: {signature_valid}")

        return decrypted_data, signature_valid

    @staticmethod
    def aes_rsa_combined_workflow(sender_rsa_key, receiver_rsa_key, shared_aes_key, plaintext):
        """
        Combined AES and RSA Workflow
        -----------------------------

        Demonstrates a hybrid cryptographic workflow that combines AES and RSA.

        Steps:
        1. Encrypt the plaintext using AES.
        2. Encrypt the AES key with the receiver's public RSA key.
        3. Sign the plaintext with the sender's private RSA key.
        4. Decrypt the AES key with the receiver's private RSA key.
        5. Decrypt the ciphertext using the decrypted AES key.
        6. Verify the signature using the sender's public RSA key.

        Parameters:
            sender_rsa_key (str): The sender's RSA key ID.
            receiver_rsa_key (str): The receiver's RSA key ID.
            shared_aes_key (str): The shared AES key ID.
            plaintext (str): The message to be secured.

        Returns:
            tuple:
                decrypted_message (str): The decrypted plaintext.
                signature_valid (bool): Whether the signature verification succeeded.

        Logs:
            - Logs each step of the combined AES-RSA workflow.
        """
        Logger.log("[Step 1] Starting AES-RSA Combined Workflow.")

        # Step 1: Encrypt the plaintext using AES
        aes_encryption_result = CryptoManager.encrypt(
            key_id=shared_aes_key,
            plaintext=plaintext,
            object_type=ObjectType.AES,
            mode=CipherMode.CBC
        )
        Logger.log(f"[Step 2] AES Encryption Result: Cipher={aes_encryption_result.cipher}, IV: {aes_encryption_result.iv}")

        # Step 2: Encrypt the AES key with the receiver's RSA public key
        encrypted_aes_key_result = CryptoManager.encrypt(
            key_id=receiver_rsa_key,
            plaintext=aes_encryption_result.kid,
            object_type=ObjectType.RSA
        )
        Logger.log(f"[Step 3] Encrypted AES Key Result: Cipher={encrypted_aes_key_result.cipher}")

        # Step 3: Sign the plaintext with the sender's private RSA key
        signed_data = CryptoManager.sign(sender_rsa_key, plaintext)
        Logger.log(f"[Step 4] Generated Signature: {signed_data}")

        # Step 4: Decrypt the AES key with the receiver's private RSA key
        decrypted_aes_key = CryptoManager.decrypt(
            receiver_rsa_key,
            encrypted_aes_key_result.cipher,
            ObjectType.RSA
        )
        Logger.log(f"[Step 5] Decrypted AES Key: {decrypted_aes_key}")

        # Step 5: Decrypt the ciphertext using the decrypted AES key
        decrypted_message = CryptoManager.decrypt(
            decrypted_aes_key,
            aes_encryption_result.cipher,
            ObjectType.AES,
            CipherMode.CBC,
            aes_encryption_result.iv
        )
        Logger.log(f"[Step 6] Decrypted Message: {decrypted_message}")

        # Step 6: Verify the signature using the sender's public RSA key
        signature_valid = CryptoManager.verify(
            sender_rsa_key,
            decrypted_message,
            signed_data
        )
        Logger.log(f"[Step 7] Signature Verification Result: {signature_valid}")

        Logger.log("[Step 8] AES-RSA Combined Workflow completed successfully.")

        return decrypted_message, signature_valid


# Main Function
def main():
    """
    Main Function
    --------------

    Entry point for the Fortanix Secure Communication Script. This function:
    1. Initializes the DSM client.
    2. Parses the workflow type from command-line arguments.
    3. Executes the appropriate cryptographic workflow based on user input.

    Workflows:
        - AES Workflow: Symmetric encryption and decryption using AES.
        - RSA Workflow: Asymmetric encryption, signing, and verification using RSA.
        - Combined Workflow: Hybrid approach combining AES and RSA.

    Logs:
        - Detailed logs for each step of the workflow.
        - Errors encountered during execution.

    Returns:
        None
    """
    try:
        Logger.log("[Step 1] Starting the script.")

        # Step 1: Initialize DSM Client
        DSMClient.initialize()

        # Step 2: Parse workflow type
        workflow = cl_args.workflow.lower()
        message = cl_args.message.lower()
        Logger.log(f"[Step 2] Workflow type parsed: {workflow}.")

        # Step 3: Execute the selected workflow
        if workflow == "aes":
            Logger.log("[Step 3] Executing AES Workflow.")
            Workflows.basic_aes_encryption(message)
        elif workflow == "rsa":
            Logger.log("[Step 3] Executing RSA Workflow.")
            Workflows.basic_rsa_workflow(message)
        elif workflow == "combined":
            Logger.log("[Step 3] Executing Advanced AES-RSA Combined Workflow.")
            sender_rsa_key = CryptoManager.create_or_retrieve_key("John's RSA Key", ObjectType.RSA, 2048)
            receiver_rsa_key = CryptoManager.create_or_retrieve_key("Priya's RSA Key", ObjectType.RSA, 2048)
            shared_aes_key = CryptoManager.create_or_retrieve_key("Shared AES Key", ObjectType.AES, 256)
            Workflows.aes_rsa_combined_workflow(sender_rsa_key, receiver_rsa_key, shared_aes_key, message)
        else:
            Logger.log(f"[Step 3] Invalid workflow type: {workflow}. Please choose 'aes', 'rsa', or 'combined'.", level="ERROR")
    except Exception as e:
        Logger.log(f"[Error] An error occurred during execution: {e}", level="ERROR")
    finally:
        Logger.log("[Complete] Script execution completed.")

if __name__ == '__main__':

    # Define the argument parser
    parser = argparse.ArgumentParser(description="Secure Communication Using Fortanix DSM")
    parser.add_argument('--api-key', required=False, help='Base64-encoded API key for DSM access')
    parser.add_argument('--api-endpoint', default=DEFAULT_API_ENDPOINT, help='Fortanix DSM API endpoint')
    parser.add_argument('--workflow', default="rsa", help="Workflow to execute: aes, rsa, combined (default: rsa)")
    parser.add_argument('--message', default="Hello Priya!", help="Plaintext message to encrypt. Default 'Hello Priya'")

    # Parse the arguments
    cl_args = parser.parse_args()

    # Environment variable fallback for API key

    cl_args.api_key = os.getenv("FORTANIX_API_KEY", cl_args.api_key)
    Logger.log(f"Using API key from environment: {os.getenv('FORTANIX_API_KEY')}", level="INFO")

    # Call the main function
    main()
