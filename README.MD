# Fortanix Secure Communication Script:

## Overview
The **Fortanix Secure Communication Script** is a Python application designed to showcase secure communication workflows using the **Fortanix Data Security Manager (DSM)**. This script demonstrates how to leverage modern cryptographic techniques, including AES, RSA, and hybrid workflows, to ensure **confidentiality**, **integrity**, and **authenticity** in message exchanges.

Whether you're a beginner in cryptography or a seasoned professional, this guide provides a step-by-step understanding of the script's functionality and how it aligns with cryptographic best practices.

---

## Features
### 1. **Key Management in DSM**
- **AES Keys**: Symmetric keys used for fast, secure message encryption.
- **RSA Keys**: Asymmetric keys for secure key exchange and digital signatures.
- **Dynamic Key Handling**: Automatically retrieves or generates required keys from DSM.

### 2. **Workflows**
The script supports three cryptographic workflows:
1. **AES Workflow**: Encrypts and decrypts messages with a symmetric AES key.
2. **RSA Workflow**: Secures messages with RSA encryption and verifies them with digital signatures.
3. **Hybrid AES-RSA Workflow**: Combines AES for efficiency and RSA for secure key exchange and verification.

### 3. **Secure Protocol Design**
The script follows a **sender-receiver model**:
- The **sender** encrypts the message, signs it, and shares the AES key securely.
- The **receiver** decrypts the key, verifies the signature, and decrypts the message.

### 4. **Comprehensive Logging**
Detailed, color-coded logs provide step-by-step insights into every operation, making the script easy to debug and understand.

---

## Cryptography Fundamentals
### 1. **AES Encryption**
- **Symmetric Encryption**: The same key is used for encryption and decryption.
- **Block Cipher**: Operates on fixed-size blocks (e.g., 128-bit).
- **Mode**: CBC (Cipher Block Chaining) mode adds an initialization vector (IV) for enhanced security.

### 2. **RSA Encryption**
- **Asymmetric Encryption**: Uses a public key for encryption and a private key for decryption.
- **Digital Signatures**: Ensures data integrity and authenticity by signing messages with a private key and verifying with the corresponding public key.

### 3. **Hybrid Cryptography**
- **AES + RSA**: Combines the speed of AES with the secure key exchange capabilities of RSA.

---

## Installation
### Prerequisites
- Python 3.8 or higher
- Fortanix DSM SDK
- Access to a configured Fortanix DSM instance

### Dependencies
Install the required Python packages:
```bash
pip install sdkms termcolor
```

---

## Usage
### Command-Line Interface
Run the script with the following parameters:
```bash
python fortanix_secure_comm_v4.py --api-key <API_KEY> --workflow <aes|rsa|combined> --message <message>
```

#### Arguments
- `--api-key`: Base64-encoded DSM API key (`<username>:<password>` format).
- `--workflow`: Specifies the cryptographic workflow to execute:
  - `aes`: AES-only encryption and decryption.
  - `rsa`: RSA-based encryption, signing, and verification.
  - `combined`: Hybrid AES-RSA workflow.
- `--message`: The plaintext message to encrypt.

---

## Example
### Encrypt and Decrypt a Message Using the AES Workflow
```bash
python fortanix_secure_comm_v4.py --api-key <your_api_key> --workflow aes --message "Hello Fortanix!"
```

### Hybrid AES-RSA Workflow
```bash
python fortanix_secure_comm_v4.py --api-key <your_api_key> --workflow combined --message "Secure Hello"
```

---

## Code Structure
### 1. **DSMClient**
Handles authentication and interaction with Fortanix DSM:
- Initializes the client using the provided API key.
- Configures and authorizes DSM API instances.

### 2. **CryptoManager**
Performs cryptographic operations:
- **Key Management**: Retrieves or generates keys in DSM.
- **Encryption and Decryption**: Secures data using AES or RSA.
- **Signing and Verification**: Ensures data integrity and authenticity.

### 3. **Workflows**
Defines pre-built workflows:
- **AES Workflow**: Demonstrates AES encryption and decryption.
- **RSA Workflow**: Uses RSA for encryption, signing, and verification.
- **Hybrid Workflow**: Combines AES and RSA for secure communication.

---

## Protocol Details
### Advanced AES-RSA Workflow
#### Steps:
1. **Sender (John)**:
   - Encrypts the message using an AES key.
   - Encrypts the AES key with Priya's RSA public key.
   - Signs the message using John's RSA private key.

2. **Receiver (Priya)**:
   - Decrypts the AES key with her RSA private key.
   - Decrypts the message using the AES key.
   - Verifies the signature using John's RSA public key.

#### Data Flow:
```plaintext
[Message (AES Key)] -> [Encrypted AES Key (RSA)] -> [Signed Message (RSA)]
```

#### Encapsulation Example:
```plaintext
Step 1: ["Hello Priya" (AES Key)]
Step 2: [["Hello Priya" (AES Key)] (John's RSA Public Key)]
Step 3: [[["Hello Priya" (AES Key)] (John's RSA Public Key)] + [Digest ("Hello Priya") Signed (John's RSA Private Key)]]
```

---

## Logging Example
The script outputs detailed logs for debugging and education:
```plaintext
[INFO] Starting the script.
[INFO] Initializing DSM client.
[INFO] DSM client configured with the following settings:
  Host: https://apps.smartkey.io
  Username: **********
[INFO] Executing Advanced AES-RSA Combined Workflow.
[INFO] Encrypting plaintext using AES.
[INFO] AES Encryption Result: Cipher=********, IV=********
...
[INFO] Script execution completed.
```

---

## Learning Points
1. **Cryptography in Practice**:
   - Understand the interplay of symmetric and asymmetric encryption.
   - Appreciate the importance of secure key management in real-world scenarios.

2. **DSM Integration**:
   - Learn how to interact with a Hardware Security Module (HSM) like Fortanix DSM.
   - Securely store and manage cryptographic keys.

3. **Secure Communication**:
   - Implement end-to-end security for message exchanges.
   - Use logging to trace operations and debug cryptographic workflows.

---

## Advanced Tips
1. **Environment Variables**:
   - Use `FORTANIX_API_KEY` for secure API key handling.
   ```bash
   export FORTANIX_API_KEY="your_api_key"
   ```

2. **Custom Workflows**:
   - Extend the `Workflows` class to define custom cryptographic workflows.

3. **Error Handling**:
   - Use detailed logs and exception handling for robust and secure execution.

---

## License
This script is licensed under the **MIT License**. See the LICENSE file for details.

---

## Conclusion
The **Fortanix Secure Communication Script** is a powerful tool to learn cryptographic principles and integrate them with enterprise-grade security systems like Fortanix DSM. By walking through this script, you’ll not only understand cryptographic fundamentals but also gain practical skills to build secure communication systems.

