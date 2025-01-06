---

# 🔐 Advanced Secure Communication Using Fortanix DSM

## 📜 Overview

This project demonstrates secure communication workflows using the **Fortanix Data Security Manager (DSM)** for cryptographic operations. It includes **three core workflows**

1. **Basic RSA Workflow**: Asymmetric encryption and signing using RSA keys.
2. **Basic AES Workflow**: Symmetric encryption and decryption using AES keys.
3. **Hybrid RSA-AES Workflow**: Combining RSA and AES for advanced secure communication.

The project is designed to **educate newcomers to cryptography** and **Fortanix DSM** while showcasing a robust, real-world implementation of secure communication protocols.

---

## 🧩 Features

### 🔑 Key Management
- **RSA Keys**
  - 2048-bit RSA keys for asymmetric encryption and signing.
- **AES Keys**
  - 256-bit AES keys for symmetric encryption.

All keys are securely stored and retrieved from the **Fortanix DSM**.

### 🔒 Secure Workflows
1. **Basic RSA Workflow**
   - Encrypt plaintext with the receiver's RSA public key.
   - Sign the plaintext with the sender's RSA private key.
   - Decrypt the ciphertext with the receiver's RSA private key.
   - Verify the signature with the sender's RSA public key.

2. **Basic AES Workflow**:
   - Encrypt plaintext with an AES key using **CBC mode**.
   - Decrypt ciphertext with the same AES key.

3. **Hybrid RSA-AES Workflow**:
   - Encrypt the message with an AES key (for efficiency).
   - Encrypt the AES key with the receiver's RSA public key (for secure key exchange).
   - Sign the plaintext with the sender's RSA private key.
   - Decrypt the AES key and message and verify the signature.

### 📋 Protocol Workflow Visualization

#### **Basic RSA Workflow**
```
[Message](RSA Public Key) → [Encrypted Message](Signed with Sender's RSA Private Key)
[Encrypted Message](RSA Private Key) → [Decrypted Message](Verified with Sender's RSA Public Key)
```

#### **Basic AES Workflow**
```
[Message](AES Key) → [Encrypted Message](AES Key)
[Encrypted Message](AES Key) → [Decrypted Message]
```

#### **Hybrid RSA-AES Workflow**
```
Step 1: Encrypt message with AES key:
[Message](AES Key)

Step 2: Encrypt AES key with RSA:
[[Message](AES Key)](Receiver's RSA Public Key)

Step 3: Sign message with RSA:
[[[Message](AES Key)](Receiver's RSA Public Key)] + [Digest(Message)](Signed with Sender's RSA Private Key)

Decryption reverses this process, with AES key decryption and message signature verification.
```

---

## 🛠️ Key Functions

### Key Management
#### `create_or_retrieve_key`
```python
@staticmethod
def create_or_retrieve_key(name, key_type, size):
    """
    Create or retrieve a key from Fortanix DSM.

    Parameters:
    - name (str): Key name to retrieve or create.
    - key_type (ObjectType): RSA or AES.
    - size (int): Key size (e.g., 2048 for RSA, 256 for AES).

    Returns:
    - str: The key ID.
    """
```

### Core Cryptographic Operations
1. **Encryption**
   ```python
   @staticmethod
   def encrypt(key_id, plaintext, object_type, mode=None, iv=None):
       """
       Encrypt plaintext using Fortanix DSM.

       Parameters:
       - key_id (str): The encryption key ID.
       - plaintext (str): Data to encrypt.
       - object_type (ObjectType): RSA or AES.
       - mode (CipherMode): Optional, for AES (e.g., CBC).

       Returns:
       - EncryptResult: Encrypted data.
       """
   ```
2. **Decryption**
   ```python
   @staticmethod
   def decrypt(key_id, ciphertext, object_type, mode=None, iv=None):
       """
       Decrypt ciphertext using Fortanix DSM.

       Parameters:
       - key_id (str): The decryption key ID.
       - ciphertext (bytearray): Encrypted data.
       - object_type (ObjectType): RSA or AES.
       - mode (CipherMode): Optional, for AES (e.g., CBC).

       Returns:
       - str: Decrypted plaintext.
       """
   ```
3. **Signing**
   ```python
   @staticmethod
   def sign(key_id, message):
       """
       Sign a message using Fortanix DSM.

       Parameters:
       - key_id (str): RSA private key ID.
       - message (str): Message to sign.

       Returns:
       - bytearray: Digital signature.
       """
   ```
4. **Signature Verification**
   ```python
   @staticmethod
   def verify(key_id, message, signature):
       """
       Verify a signature using Fortanix DSM.

       Parameters:
       - key_id (str): RSA public key ID.
       - message (str): Original message.
       - signature (bytearray): Signature to verify.

       Returns:
       - bool: True if valid, False otherwise.
       """
   ```

---

## 💻 Workflows

### 1️⃣ Basic RSA Workflow
```python
SecureWorkflow.basic_rsa_workflow()
```
1. **Encrypt message** with receiver's RSA public key.
2. **Sign message** with sender's RSA private key.
3. **Decrypt message** with receiver's RSA private key.
4. **Verify signature** with sender's RSA public key.

---

### 2️⃣ Basic AES Workflow
```python
SecureWorkflow.basic_aes_workflow()
```
1. **Encrypt message** with AES key.
2. **Decrypt message** with the same AES key.

---

### 3️⃣ Hybrid RSA-AES Workflow
```python
SecureWorkflow.hybrid_rsa_aes_workflow()
```
1. **Encrypt message** with AES key.
2. **Encrypt AES key** with receiver's RSA public key.
3. **Sign message** with sender's RSA private key.
4. **Decrypt AES key** with receiver's RSA private key.
5. **Decrypt message** with AES key.
6. **Verify signature** with sender's RSA public key.

---

## 🔍 Logging and Debugging
All workflows include **step-by-step logging** with clear messages and color-coded levels for:
- Encryption and decryption steps.
- Key creation and retrieval from DSM.
- Signature generation and verification.

---

## 🚀 How to Run
1. Ensure **Fortanix DSM** is set up and accessible.
2. Install dependencies:
   ```bash
   pip install fortanix-sdkms termcolor
   ```
3. Execute the script:
   ```bash
   python secure_communication.py --api-key <Base64-Encoded-API-Key> --api-endpoint <DSM-Endpoint> --debug
   ```

---

## 🌟 Future Enhancements
1. **Support for Additional Algorithms**:
   - Support for Elliptic Curve Cryptography (ECC).
   - Use of GCM for authenticated AES encryption.
2. **Performance Improvements**:
   - Batch processing for multiple messages.
3. **Advanced Features**:
   - Secure key rotation.
   - Integration with hardware security modules (HSM).
   - Multi-recipient encryption.

---

## 📜 License
This project is licensed under the MIT License.

--- 

Feel free to modify or expand this README to further align with organizational needs.
