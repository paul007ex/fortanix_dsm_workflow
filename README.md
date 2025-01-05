

# Fortanix Secure Communication Example

This project demonstrates how to establish secure communication between two parties, John and Priya, using the Fortanix SDK and Data Security Manager (DSM). It showcases cryptographic operations including key management, encryption, signing, decryption, and signature verification.

The entire workflow is consolidated into a single script for clarity and ease of execution, leveraging Fortanix's powerful SDK to ensure compliance, security, and performance.

---

## Key Features

### 🔑 Key Management
- Securely generate or retrieve RSA keys for John and Priya from Fortanix DSM hosted at `https://apps.smartkey.io`.

### 🔒 Encryption
- Encrypt plaintext messages using Priya's RSA public key stored in the DSM.

### 🖋️ Signing
- Sign plaintext messages using John's RSA private key stored in the DSM.

### 🔓 Decryption
- Decrypt ciphertext using Priya's RSA private key stored in the DSM.

### ✅ Signature Verification
- Verify the authenticity of the message using John's RSA public key retrieved from the DSM.

---

## Prerequisites

### Environment Requirements
- Python 3.8+
- Fortanix SDK for Python (`sdkms`)

### Fortanix Account
- A Fortanix DSM account at `https://apps.smartkey.io`
- A valid API key in the format `base64-encoded 'username:password'`

### Install Dependencies
Install the required Python libraries using:
```bash
pip install -r requirements.txt
```

---

## File Overview

### `fortanix_secure_comm_v1.py`
This single script consolidates all necessary operations, including:
- Initialization of the Fortanix SDK
- Key management
- Cryptographic operations (encryption, signing, decryption, and verification)

---

## Workflow Explanation

### ASCII Flow Diagram with Fortanix DSM Integration

```plaintext
+---------------------------+                                   +---------------------------+
|       Fortanix DSM        |                                   |       Fortanix DSM        |
|  https://apps.smartkey.io |                                   |  https://apps.smartkey.io |
+---------------------------+                                   +---------------------------+
         |                                                             |
   Retrieve Key: "John's RSA Key"                               Retrieve Key: "Priya's RSA Key"
         |                                                             |
         v                                                             v
+---------+                                   +---------+             +---------+
|   John  |                                   |  Priya  |             |  Priya  |
+---------+                                   +---------+             +---------+
     |                                             |                        |
Encrypt "Hello Priya!" with                        |                        |
Priya's RSA Public Key                              |                        |
     +-------------------------------------------> | Step 1: Receive Encrypted Message
     |                                             |                        |
Sign Plaintext with                                v                        |
John's RSA Private Key                        Decrypt Ciphertext            |
     +------------------------------------------->| with Priya's Private Key|
     |                                             |                        |
     |                                             v                        |
Verify Signature with John's RSA Public Key  Verify Integrity of Decrypted Message
```

---

## Step-by-Step Workflow

1. Key Management:
   - Retrieve or generate RSA keys for John and Priya. If the keys already exist, their `key_id` is retrieved from Fortanix DSM.

2. Message Encryption:
   - John encrypts the plaintext message (`"Hello Priya!"`) using Priya's RSA public key.

3. Message Signing:
   - John signs the plaintext message using his RSA private key.

4. Message Decryption:
   - Priya decrypts the ciphertext using her RSA private key.

5. Signature Verification:
   - Priya verifies the signature using John's RSA public key, ensuring authenticity and message integrity.

---

## Running the Script

### Execution
Run the consolidated script:
```bash
python fortanix_secure_comm_v1.py --api-key <base64-encoded-API-key>
```

### Output Example
```plaintext
Checking if key with name 'johns rsa key' already exists...
Key with name 'johns rsa key' already exists. Skipping creation.
Checking if key with name 'priya's rsa key' already exists...
Key with name 'priya's rsa key' already exists. Skipping creation.
john_key_id: e91c80b6-8045-4f99-a8de-fd218a21f740
priya_key_id: 4abf50e1-9342-4b85-b134-2bc10c3ef120
Encrypting data...
Ciphertext sent to Priya: bytearray(b'...')
Signing digest...
Signed message with John's key: bytearray(b'...')
Decrypting data...
Decrypted message with Priya's private key: Hello Priya!
Decryption successful. Message integrity verified.
Generating digest...
Digest generated: bytearray(b'...')
Verifying signature...
Signature verified successfully.
```

---

## Key Functions in Detail

### Key Management
- `create_key_check_existing`:
   - Retrieves an existing key by name or creates a new RSA key in the DSM.

### Encryption and Decryption
- `encrypt`:
   - Encrypts plaintext using the recipient's public key stored in the DSM.
- `decrypt`:
   - Decrypts ciphertext using the recipient's private key stored in the DSM.

### Signing and Verifying
- `sign_digest`:
   - Signs a plaintext message using the sender's private key stored in the DSM.
- `verify_digest_signature`:
   - Verifies a message's signature using the sender's public key retrieved from the DSM.

---

## Testing the Workflow

### Validation Scenarios

1. Successful Workflow:
   - Verify the decrypted message matches the original plaintext.
   - Ensure signature verification passes.

2. Tampered Ciphertext:
   - Modify the ciphertext and observe decryption failure.

3. Invalid Signature:
   - Modify the signature and observe verification failure.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
