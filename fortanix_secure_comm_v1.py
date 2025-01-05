#!/usr/bin/python


from __future__ import print_function

import pprint
from termcolor import colored  # Ensure termcolor is installed for color support

import argparse
import base64
import os
import sys
import sdkms
import pprint

import sdkms.v1

from sdkms.v1.models.cipher_mode import CipherMode
from sdkms.v1.models.object_type import ObjectType
from sdkms.v1.models.digest_algorithm import DigestAlgorithm
from sdkms.v1.models.elliptic_curve import EllipticCurve


DEFAULT_API_ENDPOINT = "https://apps.smartkey.io"
DEBUG = False

ca_certificate = None

# Global API instance dict.
api_instances = {}

# Unique ID to append to key names to make sure they're unique.
my_unique_id = base64.b64encode(bytearray(os.urandom(16))).decode('ascii')

# Global set of keys created by the test, will be cleaned up automatically.
keys = []

iv = bytearray(os.urandom(16))
plain = bytearray(os.urandom(32))

def print_debug(*args, level="INFO", **kwargs):
    """
    Enhanced debug printing function with support for log levels and color-coded output.

    Parameters:
    - *args: Positional arguments to be printed.
    - level (str): Log level indicating the type of message. Default is "INFO".
                   Supported levels: "INFO", "WARNING", "ERROR", "TRACE", "EXCEPTION".
    - **kwargs: Additional keyword arguments passed to the PrettyPrinter instance.

    Behavior:
    - Prints the message with the appropriate color based on the log level.
    - If `cl_args.debug` is set to True, debug messages will be displayed.

    Color Mapping:
    - INFO: Green
    - WARNING: Yellow
    - ERROR: Red
    - TRACE: Blue
    - EXCEPTION: Magenta
    """
    if cl_args.debug:
        # Color mapping for different log levels
        color_map = {
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "TRACE": "blue",
            "EXCEPTION": "magenta"
        }

        # Default to white if the level is not recognized
        color = color_map.get(level.upper(), "white")

        # Prefix the log message with the level
        level_prefix = f"[{level.upper()}]"

        # Create a PrettyPrinter instance for formatted output
        pp = pprint.PrettyPrinter(indent=4)

        # Print each argument with the level prefix and colorized text
        for arg in args:
            print(level_prefix, colored(pp.pformat(arg), color))

def print_debug_old (*args, **kwargs):
    if cl_args.debug:
        pp = pprint.PrettyPrinter(indent=4)  # Create a PrettyPrinter instance
        for arg in args:
            pp.pprint(arg)

   
def get_api_instance(name):
    return api_instances[name]
    
def parse_arguments():
    parser = argparse.ArgumentParser(description='SDKMS API perf/stress test')

    # This construction allows us to use the API endpoint if it's specified
    # on the command-line, then use the environment variable if it's set,
    # then use the program-default endpoint if neither is set.
    parser.add_argument('--api-endpoint',
                        default=os.getenv('FORTANIX_API_ENDPOINT',
                                          DEFAULT_API_ENDPOINT))

    parser.add_argument('--api-key',
                        default=os.getenv('FORTANIX_API_KEY', None))
    parser.add_argument('--debug', default=False, action='store_true',
                        help='enable debug logging')
    parser.add_argument('--no-verify-ssl', default=True, action='store_false',
                        dest='verify_ssl',
                        help='Disables SSL verification. Useful for '
                        'locally running SDKMS')
    parser.add_argument('--ca-certificate', help='Set the CA certificate to be'
                        'used for the TLS root of trust')

    global cl_args
    cl_args = parser.parse_args()

    if cl_args.api_key is None:
        print('No API key specified.')
        print('Please specify an API key via the --api-key option or '
              'FORTANIX_API_KEY')
        print('environment variable')
        exit(1)

    global ca_certificate
    if cl_args.ca_certificate:
        ca_certificate = cl_args.ca_certificate

def initialize_dsm_client():
    """
    Initializes DSM api clients and authenticates with the Fortanix Data Security Manager (DSM).

    This function handles the decoding, parsing, and configuration of credentials required
    to interact with the DSM. It authenticates using a Base64-encoded API key and retrieves
    an access token, which is used for subsequent secure API calls. The function also configures
    additional parameters such as the DSM endpoint and SSL settings.

    Steps:
    1. Decode the Base64 API key to retrieve the username and password.
    2. Parse the decoded credentials into separate username and password fields.
    3. Create a configuration object for the DSM interaction, setting:
       - Username and password for authentication.
       - DSM endpoint (default: https://apps.smartkey.io).
       - Optional SSL certificate for secure communication.
       - Debugging settings for logging detailed output if enabled.
    4. Use the configuration to create an API client instance.
    5. Authenticate with the DSM using the `AuthenticationApi` and retrieve an access token.
    6. Store the access token in the client configuration for secure API requests.

    DSM Interaction:
    - The DSM validates the credentials provided (username and password).
    - Upon successful authentication, it returns a short-lived access token.
    - This access token is included in the `Authorization` header of all subsequent requests.

    Secure Communication:
    - All communication with the DSM occurs over HTTPS, ensuring confidentiality and integrity.
    - Optionally, an SSL/TLS certificate can be provided for additional verification.

    Parameters:
    None (Relies on globally accessible arguments and configuration variables.)

    Raises:
    - ValueError: If the API key format is invalid (e.g., missing the colon separator).
    - HTTPError: If authentication with the DSM fails (e.g., due to incorrect credentials).

    Example Workflow:
    1. Input:
       - Base64 API key: `dXNlcjEyMzpwYXNzd29yZDQ1Ng==` (decoded as `user123:password456`).
       - DSM endpoint: `https://apps.smartkey.io`.
    2. Steps:
       - Decode API key → Parse credentials → Authenticate with DSM → Retrieve access token.
    3. Output:
       - Access token: `Bearer eyJhbGciOiJIUzI1NiIs...`.

    Notes:
    - This function is critical for establishing secure communication with the DSM.
    - The access token must be securely stored in memory and not exposed unnecessarily.
    - Ensure the DSM endpoint is reachable and correctly configured.

    """

    api_key = base64.b64decode(cl_args.api_key).decode('ascii')
    print_debug('Using API key {}'.format(api_key))
   # exit(1)
    parts = api_key.split(':')
    if len(parts) != 2:
        print('Invalid API key provided')
        exit(1)

    config = sdkms.v1.configuration.Configuration()
    config.username = parts[0]
    config.password = parts[1]
    config.debug = cl_args.debug
    if ca_certificate:
        config.ssl_ca_cert = ca_certificate

    print_debug('API key components: {} {}'.format(config.username,
                                                   config.password))

    config.verify_ssl = cl_args.verify_ssl

    print_debug('Using API endpoint {}'.format(cl_args.api_endpoint))
    config.host = cl_args.api_endpoint

    client = sdkms.v1.ApiClient(configuration=config)

    client.configuration.debug = DEBUG

    auth_instance = sdkms.v1.AuthenticationApi(api_client=client)
    auth = auth_instance.authorize()
    print_debug(auth)

    # The swagger interface calls this type of authorization an 'apiKey'.
    # This is not related to the SDKMS notion of an API key. The swagger
    # apiKey is our auth token.
    config.api_key['Authorization'] = auth.access_token
    config.api_key_prefix['Authorization'] = 'Bearer'

    api_instances['auth'] = auth_instance
    api_instances['sobjects'] = sdkms.v1.SecurityObjectsApi(
        api_client=client)
    api_instances['crypto'] = sdkms.v1.EncryptionAndDecryptionApi(
        api_client=client)
    api_instances['signverify'] = sdkms.v1.SignAndVerifyApi(
        api_client=client)
    api_instances['digest'] = sdkms.v1.DigestApi(api_client=client)
    api_instances['sobjects'] = sdkms.v1.SecurityObjectsApi(
        api_client=client)
    
    print_debug(api_instances)
   # exit(1)

def create_key_check_existing(key_type, size, name=None, elliptic_curve=None):
    # Check if a key with the given name already exists
    if name:
        print(f"Checking if key with name '{name}' already exists...")
        #all_keys = get_api_instance('sobjects').list_security_objects()
        all_keys = get_api_instance('sobjects').get_security_objects()

        for key in all_keys:
            if key.name == name:
                print(f"Key with name '{name}' already exists. Skipping creation.")
                return key.kid  # Return the existing key ID
    
    # If no name is provided or the key doesn't exist, create a new one
    keynum = len(keys)
    key_name = name if name else 'new-test-key-{}-{}-{}-{}'.format(my_unique_id, key_type.value, size, keynum)
    print(f"Creating a new key with name '{key_name}'...")
    
    request = sdkms.v1.SobjectRequest(
        name=key_name,
        description='Generated key for secure communication',
        key_size=size, obj_type=key_type, elliptic_curve=elliptic_curve
    )
    kid = get_api_instance('sobjects').generate_security_object(request).kid
    
    # Add the key ID to the global list for cleanup
    keys.append(kid)
    return kid

def support_sign_verify(object_type):
    if object_type in [ObjectType.RSA, ObjectType.EC]:
        return True
    return False


def encrypt(key_id, plain, object_type, mode=None):
    """
    Encrypts plaintext data using a key stored in the Fortanix DSM.

    This function performs encryption of the provided plaintext (`plain`) using
    the specified cryptographic object (`object_type`) and an encryption key identified
    by its unique key ID (`key_id`). The encryption is performed via the DSM's API.

    Parameters:
    - key_id (str): The unique identifier (UUID) of the encryption key stored in the DSM.
    - plain (bytearray): The plaintext data to be encrypted. Must be provided as a bytearray.
    - object_type (sdkms.v1.models.object_type.ObjectType): Specifies the type of encryption
      algorithm to use, e.g., RSA or AES.
    - mode (sdkms.v1.models.cipher_mode.CipherMode, optional): The mode of operation for encryption
      (e.g., ECB, CBC, GCM). Defaults to `None`, which uses the default mode for the specified object type.

    Returns:
    - tuple:
        - cipher (bytearray): The ciphertext resulting from the encryption operation.
        - iv (bytearray): The initialization vector (IV) used during encryption (if applicable).

    Steps:
    1. Constructs an `EncryptRequest` object:
        - Specifies the encryption algorithm (`alg`), mode (`mode`), and plaintext (`plain`).
    2. Retrieves the API client for cryptographic operations (`crypto`) using `get_api_instance`.
    3. Calls the `encrypt` method on the DSM's API, passing the key ID and the encryption request.
    4. Receives the encryption result, which contains the ciphertext (`cipher`) and IV (`iv`).
    5. Returns the ciphertext and IV to the caller.

    Notes:
    - The key specified by `key_id` must already exist in the DSM and support encryption.
    - The plaintext must be passed as a bytearray; if provided as a string, convert it using:
      `bytearray(your_string, 'utf-8')`.
    - The IV is only applicable for certain modes of operation (e.g., CBC, GCM). For modes
      like RSA encryption, the IV may be `None`.

    Example:
        # Define plaintext message and convert to bytearray
        plaintext = "Hello, Priya!"
        byte_message = bytearray(plaintext, 'utf-8')

        # Encrypt the plaintext using Priya's RSA key
        ciphertext, iv = encrypt(
            key_id="1234-abcd-5678-efgh",
            plain=byte_message,
            object_type=ObjectType.RSA
        )

    Raises:
    - sdkms.v1.exceptions.ApiException: If the DSM encryption API call fails.
    """
    print("Encrypting data...")

    # Step 1: Create an EncryptRequest object with the provided parameters
    encrypt_request = sdkms.v1.EncryptRequest(
        alg=object_type,  # Specify the encryption algorithm (e.g., RSA or AES)
        mode=mode,        # Specify the mode of operation (optional)
        plain=plain       # Provide the plaintext to be encrypted
    )
    print_debug(f"encrypt_result: {encrypt_request} ")

    # Step 2: Get the API client instance for cryptographic operations
    encrypt_result = get_api_instance('crypto').encrypt(key_id, encrypt_request)

    # Step 3: Log the encryption result for debugging purposes
    print_debug(f"encrypt_result: {encrypt_result} ")

    # Step 4: Return the ciphertext and initialization vector (if applicable)
    return encrypt_result.cipher, encrypt_result.iv

def decrypt(key_id, cipher, object_type, mode=None, iv=None):
    """
    Decrypts ciphertext data using a key stored in the Fortanix DSM.

    This function takes encrypted data (`cipher`) and decrypts it using the specified 
    cryptographic object (`object_type`) and a decryption key identified by its unique 
    key ID (`key_id`). Decryption is performed via the DSM's API.

    Parameters:
    - key_id (str): The unique identifier (UUID) of the decryption key stored in the DSM.
    - cipher (bytearray): The encrypted data (ciphertext) to be decrypted. Must be provided as a bytearray.
    - object_type (sdkms.v1.models.object_type.ObjectType): Specifies the type of cryptographic
      algorithm to use for decryption. Common values include:
        - `ObjectType.RSA`: For RSA decryption.
        - `ObjectType.AES`: For AES decryption.
        - `ObjectType.EC`: For Elliptic Curve Cryptography (ECC).
        - Other supported algorithms based on DSM capabilities.
    - mode (sdkms.v1.models.cipher_mode.CipherMode, optional): The mode of operation used during encryption
      (e.g., ECB, CBC, GCM). Defaults to `None`, which uses the default mode for the specified object type.
    - iv (bytearray, optional): The initialization vector (IV) used during encryption. Required for modes
      like CBC or GCM. For algorithms like RSA, this parameter is not used and can be `None`.

    Returns:
    - plain (bytearray): The decrypted plaintext resulting from the decryption operation.

    Steps:
    1. Constructs a `DecryptRequest` object:
        - Specifies the decryption algorithm (`alg`), mode (`mode`), ciphertext (`cipher`), and IV (`iv`).
    2. Retrieves the API client for cryptographic operations (`crypto`) using `get_api_instance`.
    3. Calls the `decrypt` method on the DSM's API, passing the key ID and the decryption request.
    4. Receives the decryption result, which contains the decrypted plaintext (`plain`).
    5. Returns the plaintext to the caller.

    Notes:
    - The key specified by `key_id` must already exist in the DSM and support decryption.
    - The ciphertext must be passed as a bytearray. If the encrypted data is in a different format, 
      it must be converted before calling this function.
    - The IV parameter is only required for certain encryption modes (e.g., CBC, GCM). Ensure the IV
      used during encryption is provided here for successful decryption.
    - The `object_type` must match the cryptographic object type associated with the specified `key_id`.

    Example:
        # Decrypt the ciphertext using Priya's RSA key
        decrypted_message = decrypt(
            key_id="5678-efgh-1234-abcd",
            cipher=ciphertext,
            object_type=ObjectType.RSA
        )

        # Convert the decrypted bytearray back to a string
        plaintext_message = decrypted_message.decode('utf-8')

    Raises:
    - sdkms.v1.exceptions.ApiException: If the DSM decryption API call fails.
    - AssertionError: If the decrypted plaintext does not match the expected value.

    """
    print("Decrypting data...")

    # Step 1: Create a DecryptRequest object with the provided parameters
    decrypt_request = sdkms.v1.DecryptRequest(
        alg=object_type,  # Specify the decryption algorithm (e.g., RSA, AES, ECC)
        mode=mode,        # Specify the mode of operation used during encryption
        cipher=cipher,    # Provide the ciphertext to be decrypted
        iv=iv             # Provide the IV if applicable (e.g., for CBC or GCM modes)
    )

    # Step 2: Get the API client instance for cryptographic operations
    decrypt_result = get_api_instance('crypto').decrypt(key_id, decrypt_request)

    # Step 3: Log the decryption result for debugging purposes
    print_debug(f"decrypt_result: {decrypt_result}")

    # Step 4: Return the decrypted plaintext
    return decrypt_result.plain


    """
    Verifies the signature of a given digest using a key stored in the Fortanix DSM.

    This function ensures the integrity and authenticity of data by verifying that the provided
    signature matches the hash (`digest`) of the data, using the public portion of the key specified
    by its unique ID (`key_id`). Verification is performed via the DSM's API.

    Parameters:
    - key_id (str): The unique identifier (UUID) of the key stored in the DSM to use for signature verification.
      This key must have signing/verification capabilities.
    - digest (bytearray): The hash (digest) of the original data. The digest must be generated using the same
      hashing algorithm that was used during signing.
    - signature (bytearray): The signature to verify, typically created using the private counterpart of the key.
    - algorithm (sdkms.v1.models.digest_algorithm.DigestAlgorithm, optional): Specifies the hashing algorithm
      used to generate the digest. Defaults to `SHA256`.

    Returns:
    - bool: Returns `True` if the signature is verified successfully, otherwise raises an exception.

    Steps:
    1. Constructs a `VerifyRequest` object:
        - Specifies the hash algorithm (`hash_alg`), the digest (`hash`), and the signature (`signature`).
    2. Retrieves the API client for signing and verification operations (`signverify`) using `get_api_instance`.
    3. Calls the `verify` method on the DSM's API, passing the key ID and the verification request.
    4. Receives the verification result, which indicates whether the signature is valid.
    5. Returns `True` if the signature is verified successfully.

    Notes:
    - The key specified by `key_id` must already exist in the DSM and support signature verification.
    - The digest and signature must be provided as bytearrays. If in a different format, convert them before calling this function.
    - The hashing algorithm used to generate the digest must match the one specified in the `algorithm` parameter.
    - The public key corresponding to the private key used for signing must be accessible in the DSM for verification to succeed.

    Example:
        # Assume `data_digest` is the hash of the data and `data_signature` is the signature
        verification_result = verify_digest_signature(
            key_id="abcd-1234-efgh-5678",
            digest=data_digest,
            signature=data_signature
        )
        print("Verification successful:", verification_result)

    Raises:
    - sdkms.v1.exceptions.ApiException: If the DSM verification API call fails.
    - Exception: If the signature does not match the digest or any other verification error occurs.

    """
    print("Verifying signature...")

    # Step 1: Create a VerifyRequest object with the provided parameters
    verify_request = sdkms.v1.VerifyRequest(
        hash_alg=algorithm,  # Specify the hashing algorithm (e.g., SHA256)
        hash=digest,         # Provide the digest (hash) of the original data
        signature=signature  # Provide the signature to verify
    )

    # Step 2: Get the API client instance for signing and verification operations
    verify_result = get_api_instance('signverify').verify(key_id, verify_request)

    # Step 3: Check the verification result
    if not verify_result.result:
        raise Exception("Signature verification failed!")

    # Step 4: Log success and return
    print("Signature verified successfully.")
    return True

def verify_digest_signature(key_id, digest, signature, algorithm=DigestAlgorithm.SHA256):
    """
    Verifies the signature of a given digest using a key stored in the Fortanix DSM.

    This function ensures the integrity and authenticity of data by verifying that the provided
    signature matches the hash (`digest`) of the data, using the public portion of the key specified
    by its unique ID (`key_id`). Verification is performed via the DSM's API.

    Parameters:
    - key_id (str): The unique identifier (UUID) of the key stored in the DSM to use for signature verification.
      This key must have signing/verification capabilities.
    - digest (bytearray): The hash (digest) of the original data. The digest must be generated using the same
      hashing algorithm that was used during signing.
    - signature (bytearray): The signature to verify, typically created using the private counterpart of the key.
    - algorithm (sdkms.v1.models.digest_algorithm.DigestAlgorithm, optional): Specifies the hashing algorithm
      used to generate the digest. Defaults to `SHA256`.

    Returns:
    - bool: Returns `True` if the signature is verified successfully, otherwise raises an exception.

    Steps:
    1. Constructs a `VerifyRequest` object:
        - Specifies the hash algorithm (`hash_alg`), the digest (`hash`), and the signature (`signature`).
    2. Retrieves the API client for signing and verification operations (`signverify`) using `get_api_instance`.
    3. Calls the `verify` method on the DSM's API, passing the key ID and the verification request.
    4. Receives the verification result, which indicates whether the signature is valid.
    5. Returns `True` if the signature is verified successfully.

    Notes:
    - The key specified by `key_id` must already exist in the DSM and support signature verification.
    - The digest and signature must be provided as bytearrays. If in a different format, convert them before calling this function.
    - The hashing algorithm used to generate the digest must match the one specified in the `algorithm` parameter.
    - The public key corresponding to the private key used for signing must be accessible in the DSM for verification to succeed.

    Example:
        # Assume `data_digest` is the hash of the data and `data_signature` is the signature
        verification_result = verify_digest_signature(
            key_id="abcd-1234-efgh-5678",
            digest=data_digest,
            signature=data_signature
        )
        print("Verification successful:", verification_result)

    Raises:
    - sdkms.v1.exceptions.ApiException: If the DSM verification API call fails.
    - Exception: If the signature does not match the digest or any other verification error occurs.

    FLOW:
    +-------------------+
    | Original Message (PRE-STEP)
    +-------------------+
              |
              v
    +-------------------+               +-------------------+
    | Generate Digest   |               | Provided Signature|
    | (e.g., SHA256)    |               |                   |
    +-------------------+               +-------------------+
              |                                 |
              v                                 |
    +-------------------+                       |
    | Digest (Hash) -> verify_digest_signature()|               
    +-------------------+                       |
              |                                 |
              v                                 |
    +-------------------------------------+     |
    | Construct VerifyRequest             |     |
    | - Digest (Hash)                     |     |
    | - Signature                         |     |
    | - Hash Algorithm (e.g., SHA256)     |     |
    +-------------------------------------+     |
              |                                 |
              v                                 |
    +-------------------------------------------+
    | Fortanix DSM                               |
    | VerifyRequest sent to DSM via API          |
    | Endpoint: /crypto/v1/keys/{key-id}/verify |
    +-------------------------------------------+
              |
              v
    +-----------------------------------+
    | DSM Verifies Signature:           |
    | - Uses Public Key for `key_id`    |
    | - Compares Digest & Signature     |
    +-----------------------------------+
              |
      +-------+-------+
      |               |
      v               v
    Success        Failure
      |               |
      v               v
    "Signature    "Signature
     Verified"    Verification
                   Failed!"

    """
    print("Verifying signature...")

    # Step 1: Create a VerifyRequest object with the provided parameters
    verify_request = sdkms.v1.VerifyRequest(
        hash_alg=algorithm,  # Specify the hashing algorithm (e.g., SHA256)
        hash=digest,         # Provide the digest (hash) of the original data
        signature=signature  # Provide the signature to verify
    )
    print_debug(f"verify_request: {verify_request}")
    # Step 2: Get the API client instance for signing and verification operations
    verify_result = get_api_instance('signverify').verify(key_id, verify_request)
    print_debug(f"verify_request: {verify_result}")
   # exit(0)

    # Step 3: Check the verification result
    if not verify_result.result:
        raise Exception("Signature verification failed!")

    # Step 4: Log success and return
    print(" Signature verified successfully.")
    return True

def validate_message_integrity(original_message, decrypted_message, verified):
    """
    Validates the integrity and authenticity of the message.

    Parameters:
    - original_message (str): The plaintext message before encryption.
    - decrypted_message (str): The message after decryption.
    - verified (bool): The result of signature verification.

    Raises:
    - ValueError: If the decrypted message does not match the original message.
    - ValueError: If the signature verification fails.

    Returns:
    - None: Prints a success message if validation passes.
    """
    print_debug("Validating message integrity...")

    # Step 1: Validate decryption
    if decrypted_message != original_message:
        raise ValueError("Decrypted message does not match the original plaintext!")
    print_debug(f"Decryption successful. Message integrity verified. Original Message: {original_message}")

    # Step 2: Validate signature verification
    if not verified:
        raise ValueError("Signature verification failed!")
    print_debug("Signature verified successfully. Message authenticity confirmed.")

    print("Message integrity and authenticity validation complete.")


def list_keys():
    print("Fetching all keys...")
    keys = get_api_instance('sobjects').list_security_objects()
    print(f"Found {len(keys)} keys.")
    return keys


def sign_digest(key_id, data, algorithm=DigestAlgorithm.SHA256):
    """
    Generates a digital signature for the given data using the specified key.

    Digital signatures ensure the integrity and authenticity of the data by 
    signing a cryptographic hash (digest) of the data with a private key.

    Parameters:
    - key_id (str): The UUID of the key stored in the DSM, used for signing. 
                    This key must be capable of signing operations (e.g., RSA or ECC private key).
    - data (bytearray): The raw data to be signed. 
                        This is typically the message or content requiring authentication.
    - algorithm (DigestAlgorithm, optional): The hashing algorithm to use for 
                                             creating the digest. Default is SHA256.

    Returns:
    - bytearray: The generated digital signature, created using the specified private key.

    Steps:
    1. **Generate a Digest**:
       - A cryptographic hash (digest) of the provided data is created using the specified hashing algorithm.
       - The digest is a fixed-size representation of the data and serves as input for signing.

    2. **Sign the Digest**:
       - The digest is signed using the private key associated with the provided `key_id`.
       - This generates a unique signature that can later be verified using the corresponding public key.

    DSM Interaction:
    - The DSM (Fortanix Data Security Manager) is responsible for performing the cryptographic operations securely.
    - The `DigestApi` of the DSM generates the cryptographic digest of the data.
    - The `SignAndVerifyApi` signs the generated digest with the private key.

    Secure Communication:
    - All communication with the DSM occurs over HTTPS, ensuring data confidentiality and integrity.
    - The `Authorization` header contains a bearer token for secure interaction.

    Example Workflow:
    1. Input:
       - `key_id`: `123e4567-e89b-12d3-a456-426614174000`
       - `data`: `bytearray(b'Hello Priya!')`
       - `algorithm`: `DigestAlgorithm.SHA256`
    2. Steps:
       - Generate digest → Sign digest.
    3. Output:
       - Signature: A bytearray representing the signed digest.

    Notes:
    - Ensure the key specified by `key_id` supports signing operations.
    - The generated signature can later be verified using the corresponding public key.

    Raises:
    - SDKMS API exceptions if the DSM operations fail (e.g., invalid key or digest).
    - ValueError if the data or key_id is invalid.

    Example Usage:
    ```python
    key_id = "123e4567-e89b-12d3-a456-426614174000"
    data = bytearray("Hello Priya!", "utf-8")
    signature = sign_digest(key_id, data)
    print(f"Generated Signature: {signature}")
    ```
    """
    # Step 1: Generate a cryptographic digest for the data
    print_debug("Generating digest...")
    digest_request = sdkms.v1.DigestRequest(
        alg=algorithm,  # Specify the hashing algorithm (default: SHA256)
        data=data       # Data to be hashed
    )
    # Perform the digest operation using the DSM
    digest = get_api_instance('digest').compute_digest(digest_request).digest
    print_debug(f"digest: {digest}")

    # Step 2: Sign the digest using the private key
    print_debug("Signing digest...")
    sign_request = sdkms.v1.SignRequest(
        hash_alg=algorithm,  # Specify the hashing algorithm
        hash=digest          # Provide the computed digest
    )
    # Perform the signing operation using the DSM
    sign_result = get_api_instance('signverify').sign(key_id, sign_request)
    print_debug(f"sign_result: {sign_result}")

    # Return the generated digital signature
    return sign_result.signature


def generate_digest(data, algorithm=DigestAlgorithm.SHA256):
    """
    Generates a digest (hash) for the given data.

    :param data: The data to hash (bytearray).
    :param algorithm: The hashing algorithm to use (default: SHA256).
    :return: The digest as a bytearray.
    """
    print("Generating digest...")
    digest_request = sdkms.v1.DigestRequest(
        alg=algorithm,
        data=data
    )
    digest_result = get_api_instance('digest').compute_digest(digest_request)
    print(f"Digest generated: {digest_result.digest}")
    return digest_result.digest


if __name__ == '__main__':
    """
    Main Function: Demonstrates the secure communication process between two entities (John and Priya)
    using Fortanix DSM for key management and cryptographic operations.

    Workflow:
    1. Parse input arguments to initialize the program configuration.
       - Input: API endpoint, API key, SSL verification settings.
       - Function: `parse_arguments()`
       - Output: Configuration variables (`cl_args`).
    
    2. Initialize the DSM client for secure communication.
       - Input: Configuration variables.
       - Function: `initialize_dsm_client()`
       - Output: API instances for interacting with DSM.

    3. Define the plaintext message to be securely transmitted.
       - Example: `message_to_priya = "Hello Priya!"`

    4. Create or retrieve cryptographic RSA keys for John and Priya.
       - Function: `create_key_check_existing()`
       - Input:
           - Key name (e.g., "johns rsa key", "priya's rsa key").
           - Key type (`RSA`).
           - Key size (e.g., 2048 bits).
       - Output: Unique Key IDs (`john_key_id`, `priya_key_id`).

    5. Encrypt the plaintext message with Priya's public key for confidentiality.
       - Function: `encrypt()`
       - Input:
           - Priya's public key ID (`priya_key_id`).
           - Plaintext message (`message_to_priya`).
           - Encryption algorithm (`RSA`).
       - Output: Ciphertext (`john_cipher_to_priya`) and optional IV.

    6. Sign the plaintext message with John's private key for authenticity.
       - Function: `sign_digest()`
       - Input:
           - John's private key ID (`john_key_id`).
           - Plaintext message (`message_to_priya`).
           - Hashing algorithm (default: `SHA256`).
       - Output: Digital signature (`signed_message_with_johns_key`).

    7. Decrypt the ciphertext with Priya's private key to retrieve the plaintext.
       - Function: `decrypt()`
       - Input:
           - Priya's private key ID (`priya_key_id`).
           - Ciphertext (`john_cipher_to_priya`).
           - Encryption algorithm (`RSA`).
       - Output: Decrypted plaintext (`decrypted_message_with_priyas_private_key`).

    8. Verify the digital signature using John's public key to confirm authenticity.
       - Function: `verify_digest_signature()`
       - Input:
           - John's public key ID (`john_key_id`).
           - Digest of the plaintext message.
           - Digital signature (`signed_message_with_johns_key`).
       - Output: Verification status (`True` if valid, raises Exception otherwise).

    9. Validate the integrity of the communication by comparing decrypted plaintext with the original message.
       - Function: `validate_message_integrity()`
       - Input:
           - Original message (`message_to_priya`).
           - Decrypted message (`decrypted_message`).
           - Signature verification result.
       - Output: Assertion and validation feedback.

    Secure Communication Flow:
    +------------------+               +-------------------+
    |   John (Sender)  |               |   Priya (Receiver)|
    +------------------+               +-------------------+
            |                                |
       [Create Keys]                      [Create Keys]
            |                                |
            v                                v
     [Encrypt Message]  ------------->  [Decrypt Message]
            |                                |
     [Sign Plaintext]                      [Verify Signature]
            |                                |
            v                                v
      [Send Cipher & Sig]          [Verify Integrity & Auth]

    """

    # Step 1: Parse arguments and initialize API clients
    parse_arguments()
    initialize_dsm_client()

    # Step 2: Define the plaintext message
    message_to_priya = 'Hello Priya!'  # The message John wants to send securely to Priya

    # Step 3: Create or retrieve RSA keys for John and Priya
    john_key_id = create_key_check_existing(ObjectType.RSA, size=2048, name='johns rsa key')
    priya_key_id = create_key_check_existing(ObjectType.RSA, size=2048, name="priya's rsa key")

    # Log retrieved or created key IDs
    print_debug(f"john_key_id: {john_key_id}", "INFO")
    print_debug(f"priya_key_id: {priya_key_id}", "INFO")

    # Step 4: Encrypt the plaintext message with Priya's public key
    john_cipher_to_priya, _ = encrypt(
        key_id=priya_key_id,
        object_type=ObjectType.RSA,
        plain=bytearray(message_to_priya, 'utf-8')
    )
    print_debug(f"Ciphertext sent to Priya: {john_cipher_to_priya}", "INFO")

    # Step 5: Sign the plaintext message with John's private key
    signed_message_with_johns_key = sign_digest(
        key_id=john_key_id,
        data=bytearray(message_to_priya, 'utf-8')
    )
    print_debug(f"Signed message with John's key: {signed_message_with_johns_key}", "INFO")

    # Step 6: Decrypt the ciphertext with Priya's private key
    decrypted_message_with_priyas_private_key = decrypt(
        key_id=priya_key_id,
        object_type=ObjectType.RSA,
        cipher=john_cipher_to_priya
    )
    decrypted_message = decrypted_message_with_priyas_private_key.decode('utf-8')
    print_debug(f"Decrypted message with Priya's private key: {decrypted_message}", "INFO")

    # Verify that the decrypted message matches the original message
    assert decrypted_message == message_to_priya, \
        f"Decrypted message does not match the original plaintext! Expected: {message_to_priya}, Got: {decrypted_message}"
    print("Decryption successful. Message integrity verified.")

    # Step 7: Verify the signature using John's public key
    message_digest = generate_digest(bytearray(message_to_priya, 'utf-8'))  # Generate digest for plaintext
    verify_digest_signature(
        key_id=john_key_id,
        digest=message_digest,
        signature=bytearray(signed_message_with_johns_key)
    )
    print("Signature verified successfully.")

