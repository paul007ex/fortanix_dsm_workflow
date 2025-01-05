#!/usr/bin/python

#from fortanix_sample_code import parse_arguments, initialize_api_clients, create_key, get_api_instance, delete_test_keys
#from fortanix_sample_code import *

from __future__ import print_function

import argparse
import base64
import os
import sys
import sdkms

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

def print_debug(*args, **kwargs):
    if cl_args.debug:
        print(*args, **kwargs)

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
#create a new key, or return existing key

def initialize_api_clients():
    # TODO: We should have a separate auth endpoint for API keys, so we
    # don't need to do this parsing in the client code.
    api_key = base64.b64decode(cl_args.api_key).decode('ascii')
   # print_debug('Using API key {}'.format(api_key))
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

   # print_debug('Using API endpoint {}'.format(cl_args.api_endpoint))
    config.host = cl_args.api_endpoint

    client = sdkms.v1.ApiClient(configuration=config)

    client.configuration.debug = True

    auth_instance = sdkms.v1.AuthenticationApi(api_client=client)
    auth = auth_instance.authorize()
   # print_debug(auth)

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
    key_name = name if name else 'basic-test-key-{}-{}-{}-{}'.format(my_unique_id, key_type.value, size, keynum)
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
    print("Encrypting data...")
    encrypt_request = sdkms.v1.EncryptRequest(
        alg=object_type,
        mode=mode,
        plain=plain
    )
    encrypt_result = get_api_instance('crypto').encrypt(key_id, encrypt_request)
    print(f"encrypt_result: {encrypt_result} ")
    return encrypt_result.cipher, encrypt_result.iv

def decrypt(key_id, cipher, object_type, mode=None, iv=None):
    print("Decrypting data...")
    decrypt_request = sdkms.v1.DecryptRequest(
        alg=object_type,
        mode=mode,
        cipher=cipher,
        iv=iv
    )
    decrypt_result = get_api_instance('crypto').decrypt(key_id, decrypt_request)
    print(f"decrypt_result: {decrypt_result}")
    return decrypt_result.plain

def verify_digest_signature(key_id, digest, signature, algorithm=DigestAlgorithm.SHA256):
    print("Verifying signature...")
    verify_request = sdkms.v1.VerifyRequest(
        hash_alg=algorithm,
        hash=digest,
        signature=signature
    )
    verify_result = get_api_instance('signverify').verify(key_id, verify_request)
    if not verify_result.result:
        raise Exception("Signature verification failed!")
    print("Signature verified successfully.")
    return True

def list_keys():
    print("Fetching all keys...")
    keys = get_api_instance('sobjects').list_security_objects()
    print(f"Found {len(keys)} keys.")
    return keys

def verify_signature(key_id, data):
    print("Generating digest...")
    digest_request = sdkms.v1.DigestRequest(
        alg=DigestAlgorithm.SHA256,
        data=data
    )
    digest = get_api_instance('digest').compute_digest(digest_request).digest
    print(f"digest: {digest}")

    print("Signing digest...")
    sign_request = sdkms.v1.SignRequest(
        hash_alg=DigestAlgorithm.SHA256,
        hash=digest
    )
    sign_result = get_api_instance('signverify').sign(key_id, sign_request)
    print(f"sign_result:{sign_result}")

    print("Verifying signature...")
    verify_request = sdkms.v1.VerifyRequest(
        hash_alg=DigestAlgorithm.SHA256,
        hash=digest,
        signature=sign_result.signature
    )
    verify_result = get_api_instance('signverify').verify(key_id, verify_request)
    if not verify_result.result:
        raise Exception("Signature verification failed!")
    print(f"verify_result: {verify_result}.")
    return True

def sign_digest(key_id, data, algorithm=DigestAlgorithm.SHA256):
    """
    Generates a signature for the given data using the specified key.

    :param key_id: The UUID of the key to use for signing.
    :param data: The data to sign (bytearray).
    :param algorithm: The hashing algorithm used (default: SHA256).
    :return: The generated signature (bytearray).
    """
    print("Generating digest...")
    # Step 1: Create a digest of the data
    digest_request = sdkms.v1.DigestRequest(
        alg=algorithm,
        data=data
    )
    digest = get_api_instance('digest').compute_digest(digest_request).digest
    print(f"digest:{digest}")

    print("Signing digest...")
    # Step 2: Sign the digest
    sign_request = sdkms.v1.SignRequest(
        hash_alg=algorithm,
        hash=digest
    )
    sign_result = get_api_instance('signverify').sign(key_id, sign_request)
    print(f"sign_result {sign_result}")
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
    # Step 1: Parse arguments and initialize API clients
    parse_arguments()
    initialize_api_clients()

    # Step 2: Define the plaintext message
    message_to_priya = 'Hello Priya!'

    # Step 3: Create or retrieve RSA keys for John and Priya
    john_key_id = create_key_check_existing(ObjectType.RSA, size=2048, name='johns rsa key')
    priya_key_id = create_key_check_existing(ObjectType.RSA, size=2048, name="priya's rsa key")

    print(f"john_key_id: {john_key_id}")
    print(f"priya_key_id: {priya_key_id}")

    # Step 4: Encrypt the plaintext message with Priya's public key
    john_cipher_to_priya, _ = encrypt(
        key_id=priya_key_id,
        object_type=ObjectType.RSA,
        plain=bytearray(message_to_priya, 'utf-8')
    )
    print(f"Ciphertext sent to Priya: {john_cipher_to_priya}")

    # Step 5: Sign the plaintext message with John's private key
    signed_message_with_johns_key = sign_digest(
        key_id=john_key_id,
        data=bytearray(message_to_priya, 'utf-8')
    )
    print(f"Signed message with John's key: {signed_message_with_johns_key}")

    # Step 6: Decrypt the ciphertext with Priya's private key
    decrypted_message_with_priyas_private_key = decrypt(
        key_id=priya_key_id,
        object_type=ObjectType.RSA,
        cipher=john_cipher_to_priya
    )
    print(f"Decrypted message with Priya's private key: {decrypted_message_with_priyas_private_key.decode('utf-8')}")

    # Verify that the decrypted message matches the original message
    assert decrypted_message_with_priyas_private_key.decode('utf-8') == message_to_priya, \
        "Decrypted message does not match the original plaintext!"
    print("Decryption successful. Message integrity verified.")

    # Step 7: Verify the signature using John's public key
    message_digest = generate_digest(bytearray(message_to_priya, 'utf-8'))  # Generate digest for plaintext
    verify_digest_signature(
        key_id=john_key_id,
        digest=message_digest,
        signature=bytearray(signed_message_with_johns_key)
    )

    print("Signature verified successfully.")
