# Fortanix DSM Workflow
💬 **Author:** Paul Volosen  
🔗 [LinkedIn](https://linkedin.com/in/paul-volosen) | ✉️ [Email](mailto:paul007ex@gmail.com)  


## Introduction 📘
The **Fortanix DSM Workflow** is a Python-based demonstration of secure communication workflows powered by the **Fortanix Data Security Manager (DSM)**. This script showcases the application of **Advanced Encryption Standard (AES)**, **Rivest-Shamir-Adleman (RSA)**, and their hybrid use in **combined encryption workflows** to achieve:

- **Confidentiality**: Ensuring the message remains private. 🔒
- **Integrity**: Guaranteeing the message is unaltered. ✅
- **Authenticity**: Verifying the sender's identity. 🛡️

Whether you're new to cryptography or exploring enterprise-grade security with Fortanix DSM, this guide offers detailed insights into the **magic of cryptography** and its practical implementations.

---

## Features ✨
### 🔑 **Key Management**
- **AES Keys**: Symmetric keys for efficient and fast encryption.
- **RSA Keys**: Asymmetric keys for secure key exchange and digital signatures.
- **Dynamic Key Handling**: Automatically retrieves or generates required keys from DSM, ensuring seamless cryptographic operations.

### 🔄 **Supported Workflows**
1. **AES Workflow**:
   - Symmetric encryption and decryption using AES.
2. **RSA Workflow**:
   - Asymmetric encryption and digital signatures using RSA.
3. **Combined AES-RSA Workflow**:
   - A hybrid approach leveraging AES for data encryption and RSA for secure key exchange and signature verification.

### 🛡️ **Security Standards**
- **Encryption Modes**:
  - **AES-CBC (Cipher Block Chaining)**: Enhances security by using an Initialization Vector (IV) to randomize encryption, preventing patterns in ciphertext. 🛡️
- **Digital Signatures**:
  - Ensures data authenticity and integrity by signing messages with a private key and verifying them with a public key.

---

## Cryptographic Foundations 🧠
### 🔐 **AES: Advanced Encryption Standard**
AES is a symmetric block cipher widely used for securing data due to its speed and strength.

- **Block Size**: Operates on fixed-size 128-bit blocks.
- **Key Sizes**: Supports 128-bit, 192-bit, and 256-bit keys (this script uses **256-bit AES** for maximum security).
- **Mode of Operation**: 
  - **CBC (Cipher Block Chaining)**:
    - Each plaintext block is XORed with the previous ciphertext block before encryption.
    - Requires an **Initialization Vector (IV)** to ensure randomness. 🌀
    - The IV is transmitted along with the ciphertext to enable decryption.

#### **AES Encryption Workflow**:
1. Generate or retrieve an AES key.
2. Encrypt the plaintext message using the AES key in CBC mode with an IV.
3. Decrypt the ciphertext using the same AES key and IV to retrieve the original plaintext.

---

### 📜 **RSA: Rivest-Shamir-Adleman**
RSA is an asymmetric encryption algorithm that uses a **key pair** (public and private keys).

- **Key Pair**:
  - **Public Key**: Used to encrypt data or verify signatures.
  - **Private Key**: Used to decrypt data or sign messages.
- **Digital Signatures**:
  - A message hash is encrypted with the sender's private key to produce the signature.
  - The recipient uses the sender's public key to verify the signature.

#### **RSA Encryption Workflow**:
1. Generate or retrieve the RSA key pair (for both sender and receiver).
2. Encrypt the plaintext message using the **receiver's public key**.
3. Sign the message using the **sender's private key**.
4. The receiver decrypts the ciphertext using their **private key** and verifies the signature using the **sender's public key**.

---

### 🔄 **Supported Workflows**

1. **AES Workflow**:
   - **Description**: Uses symmetric encryption (AES) for encrypting and decrypting messages. The encryption leverages a randomly generated Initialization Vector (IV) for added security.
   - **Steps**:
     - Retrieve or create an AES key in DSM.
     - Encrypt plaintext with the AES key and IV.
     - Decrypt ciphertext with the same AES key and IV.

2. **RSA Workflow**:
   - **Description**: Implements asymmetric cryptography to encrypt data and create digital signatures. Public keys are used for encryption and signature verification, while private keys are used for decryption and signing.
   - **Steps**:
     - Retrieve or create RSA key pairs for sender and receiver in DSM.
     - Encrypt plaintext with the receiver's public key.
     - Sign the message hash with the sender's private key.
     - Decrypt the ciphertext using the receiver's private key and verify the signature with the sender's public key.

3. **Combined AES-RSA Workflow**:
   - **Description**: Combines the efficiency of AES for encrypting messages with the security of RSA for encrypting the AES key and verifying the sender's identity.
   - **Steps**:
     - Encrypt the message with AES using a shared AES key and IV.
     - Encrypt the AES key using the receiver's RSA public key.
     - Sign the original plaintext message hash with the sender's RSA private key.
     - Decrypt the AES key with the receiver's RSA private key, decrypt the ciphertext with AES, and verify the signature.

---

### 🛠️ **Classes Overview**

1. **CryptoManager**:
   - Centralizes cryptographic operations such as encryption, decryption, signing, and signature verification.
   - Manages the creation and retrieval of AES and RSA keys from Fortanix DSM.
   - Provides modular and reusable functions for secure communication workflows.

   **Key Features**:
   - **create_or_retrieve_key**:
     Handles secure key management in DSM by retrieving existing keys or creating new ones dynamically.
   - **encrypt**:
     Provides both symmetric (AES) and asymmetric (RSA) encryption functionality.
   - **decrypt**:
     Allows decryption of ciphertext using AES or RSA, depending on the encryption workflow.
   - **sign**:
     Creates digital signatures to ensure message authenticity and integrity.
   - **verify**:
     Verifies digital signatures to confirm message authenticity.

2. **Workflows**:
   - Encapsulates high-level implementations of AES, RSA, and combined encryption workflows.
   - Calls `CryptoManager` functions for cryptographic operations while managing the flow between encryption, decryption, signing, and verification steps.

---

### 🔐 **How DSM Ensures Secure Key Management**

The **Fortanix Data Security Manager (DSM)** acts as the backbone for secure cryptographic operations by providing:

1. **Centralized Key Storage**:
   - All cryptographic keys (AES and RSA) are securely stored within DSM, ensuring protection against unauthorized access.
   - Keys are never exposed outside DSM during operations.

2. **Secure Key Retrieval**:
   - The `create_or_retrieve_key` function ensures seamless access to keys by retrieving existing ones or creating new ones dynamically as needed.

3. **Hardware Security Module (HSM) Backing**:
   - DSM integrates with HSMs to provide hardware-level encryption and secure storage of cryptographic materials.

4. **Role-Based Access Control (RBAC)**:
   - DSM enforces granular access control, ensuring only authorized applications or users can perform cryptographic operations.

5. **Auditability**:
   - DSM logs all key usage and cryptographic operations, allowing for compliance and forensic analysis.

---

### 📋 **Future Potential Enhancements for Cryptographic Agility**

1. **Algorithm Flexibility**:
   - Extend support for additional encryption algorithms like AES-GCM, ECC (Elliptic Curve Cryptography), or ChaCha20 for broader compatibility.

2. **Configurable Key Sizes**:
   - Allow dynamic key size selection for AES and RSA during key creation to support a wider range of security requirements.

3. **Multiple Modes of Operation**:
   - Incorporate support for AES-GCM, AES-CTR, or RSA-OAEP to enhance security and performance for specific use cases.

4. **Key Rotation**:
   - Implement automatic key rotation policies to periodically refresh keys for improved security.

5. **Versioning of Keys**:
   - Track key versions to allow for backward compatibility and rollback during key rotation.

6. **Cross-Platform Key Management**:
   - Extend DSM integration to include support for cloud-native key management systems like AWS KMS or Azure Key Vault for hybrid deployments.

7. **Quantum-Resistant Algorithms**:
   - Explore quantum-safe encryption schemes to future-proof the solution.

8. **Custom Signing Algorithms**:
   - Allow the flexibility to select signing algorithms, such as ECDSA or EdDSA, based on application needs.

---
## How It Works

This project demonstrates secure communication workflows using **Fortanix DSM**, implementing cryptographic best practices for **confidentiality**, **integrity**, and **authenticity** of messages.

### Protocol Overview
The following steps detail the secure communication protocol used in this project:

1. **Initialization:**  
   - Parse API credentials and workflow type.  
   - Authenticate with the Fortanix DSM.  
   - Retrieve or create cryptographic keys (AES and RSA).

2. **Sender Workflow:**  
   - Encrypt the message using AES for fast and efficient encryption.  
   - Encrypt the AES key using the receiver's RSA public key for secure key exchange.  
   - Sign the original plaintext message using the sender's RSA private key for integrity.

3. **Receiver Workflow:**  
   - Decrypt the AES key using the receiver's RSA private key.  
   - Decrypt the ciphertext using the decrypted AES key to retrieve the plaintext.  
   - Verify the sender's signature using their public RSA key.

---

###  Data Flow Visualization

Below is a wireframe to illustrate the data flow between **Sender** (John) and **Receiver** (Priya) during the combined AES-RSA workflow:

```plaintext
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

### Encapsulation Example 🗳️
#### **Advanced AES-RSA Workflow**:
1. **Step 1**: AES Encryption of plaintext:
   ```
   ["Hello Priya"](AES Key)
   ```
2. **Step 2**: Encrypt the AES key with RSA:
   ```
   [["Hello Priya"](AES Key)](John's RSA Public Key)
   ```
3. **Step 3**: Sign the plaintext with RSA:
   ```
   [[["Hello Priya"](AES Key)](John's RSA Public Key)] + [Digest("Hello Priya") Signed (John's RSA Private Key)]
   ```

---

## Installation and Setup ⚙️
### Prerequisites 📋
1. Python 3.8+ 🐍
2. Fortanix DSM SDK 🛠️
3. Access to a configured **Fortanix DSM** instance. 🔐

### Installation 📦
Install the required Python dependencies:
```bash
pip install sdkms termcolor
```

---

## Usage 🚀
Run the script using the following command:
```bash
python fortanix_dsm_workflowpy --api-key <API_KEY> --workflow <aes|rsa|combined> --message <message>
```

#### Example Commands
1. **AES Workflow**:
   ```bash
   python fortanix_dsm_workflow.py --api-key <API_KEY> --workflow aes --message "Hello AES!"
   ```
2. **RSA Workflow**:
   ```bash
   python fortanix_dsm_workflow.py --api-key <API_KEY> --workflow rsa --message "Hello RSA!"
   ```
3. **Combined Workflow**:
   ```bash
   python fortanix_dsm_workflow.py --api-key <API_KEY> --workflow combined --message "Secure Hello!"
   ```

---

## Logging and Debugging 🛠️
Detailed logs guide you through every step:
```plaintext
[INFO] [Step 1] Starting the script.
[INFO] [Step 1] Initializing the DSM client.
[INFO] [Step 2] API key decoded successfully.
[INFO] [Step 3] DSM client configured with the following settings:
host: https://apps.smartkey.io
api_key: {}
api_key_prefix: {}
username: ******
password: ******
app_api_key: 
logger: {'package_logger': <RootLogger root (WARNING)>, 'urllib3_logger': <Logger urllib3 (WARNING)>}
_Configuration__logger_format: %(asctime)s %(levelname)s %(message)s
logger_formatter: <logging.Formatter object at 0x10a6e8190>
logger_stream_handler: <StreamHandler <stderr> (NOTSET)>
_Configuration__debug: False
verify_ssl: True
safe_chars_for_path_param: 
[INFO] [Step 4] Authentication successful. Access token retrieved.
[INFO] [Step 5] DSM API instances initialized successfully.
[INFO] [Step 2] Workflow type parsed: rsa.
[INFO] [Step 3] Executing RSA Workflow.
[INFO] [Step 1] Starting Basic RSA Workflow.
[INFO] Checking if key 'John's RSA Key' exists.
[INFO] Retrieving API instance for: sobjects
[INFO] Key 'John's RSA Key' found with ID: 8aa49bfa-a3a4-44eb-b830-b703c39c5ca9
[INFO] [Step 2] Sender's RSA Key created or retrieved.
[INFO] Checking if key 'Priya's RSA Key' exists.
[INFO] Retrieving API instance for: sobjects
[INFO] Key 'Priya's RSA Key' found with ID: 80656b4a-5e52-446b-a144-c52bc41e89c9
[INFO] [Step 3] Receiver's RSA Key created or retrieved.
[INFO] Encrypting the following plaintext: @@@@\n.
[INFO] Retrieving API instance for: crypto
[INFO] Encryption successful. Ciphertext: bytearray(b'0\x9f\x91r\xc2\x08\xb8\x05*\xba\xec4;h\xe1\xe6+\xf9\xed\x92\xac\x86-\xa6h\x90\x06*\xce\xaf\x8eO\x7fE\xc9'\xd1T#I\xed\xfa\x13P\xd0#CMJ|\xa7B%qq\xd5\x7f\x8b\xc68\xef\x02 \xf7\x19\x9f\x87n\x83U\xab\x8a\xc3.\xcdGy\xb4\x10\xf3\xc2\x16\x98\x1ab\xaf\x90\xa4\xba\xd4\xb2\xdc\xb3\x0f\xccR]\xac\xea\xba\x99"\x85\xff\xc8\xf3\x97\xf4N\x91\xb9\xe0\xc4B\xa6\xd3\xc4jji\xfe\xe9>\xe2\x9d\xf3\xf8+q\xc1\xe3\x0b'\x91r\x01\x8c\xba\xc6d\xbf\xdc6>\xc3\x9d\x0b\x11\xd7\xef\xad5\x98\xd0!\xfe\xeb\xb6l\xac\xa0\xfbG\xa3\x1az\xed+\xdc\xd3\xbb\xa2\xa7\x8a\xd2\xff \xdf\x9a\x97?\xf4D\xb2\xf9\xdcY\\\xe6\x10\x05Q\xe9\xd1\xf2\x86\x9d[\xbe\xe5q\x93\x1c]\xc8\x1d\xcdH\xed\x0e\xa6\xca3\x14\xff\x8b\xef\xb8\x85\x9a\x1d\xfdi\x8a\x96\xe3\xb8\x83*D=^}\xe1\xc4\xc6\xcc\xc1\x0b\x93\x96\x8e\xee\xbb,G/\xb6\x19\r\xed\x85@\xe1\x19\xc5')
[INFO] [Step 4] RSA Encryption Result: Cipher=bytearray(b'0\x9f\x91r\xc2\x08\xb8\x05*\xba\xec4;h\xe1\xe6+\xf9\xed\x92\xac\x86-\xa6h\x90\x06*\xce\xaf\x8eO\x7fE\xc9'\xd1T#I\xed\xfa\x13P\xd0#CMJ|\xa7B%qq\xd5\x7f\x8b\xc68\xef\x02 \xf7\x19\x9f\x87n\x83U\xab\x8a\xc3.\xcdGy\xb4\x10\xf3\xc2\x16\x98\x1ab\xaf\x90\xa4\xba\xd4\xb2\xdc\xb3\x0f\xccR]\xac\xea\xba\x99"\x85\xff\xc8\xf3\x97\xf4N\x91\xb9\xe0\xc4B\xa6\xd3\xc4jji\xfe\xe9>\xe2\x9d\xf3\xf8+q\xc1\xe3\x0b'\x91r\x01\x8c\xba\xc6d\xbf\xdc6>\xc3\x9d\x0b\x11\xd7\xef\xad5\x98\xd0!\xfe\xeb\xb6l\xac\xa0\xfbG\xa3\x1az\xed+\xdc\xd3\xbb\xa2\xa7\x8a\xd2\xff \xdf\x9a\x97?\xf4D\xb2\xf9\xdcY\\\xe6\x10\x05Q\xe9\xd1\xf2\x86\x9d[\xbe\xe5q\x93\x1c]\xc8\x1d\xcdH\xed\x0e\xa6\xca3\x14\xff\x8b\xef\xb8\x85\x9a\x1d\xfdi\x8a\x96\xe3\xb8\x83*D=^}\xe1\xc4\xc6\xcc\xc1\x0b\x93\x96\x8e\xee\xbb,G/\xb6\x19\r\xed\x85@\xe1\x19\xc5')
[INFO] Signing data.
[INFO] Retrieving API instance for: digest
[INFO] Retrieving API instance for: signverify
[INFO] Signature generated: bytearray(b'P\xd1\xffZ\xaai20g\x05\x82\xe3!\xc0=\xfbK\nk\'G\x01\xa7\x14\x1e\xdc:\x9c\xac\xb7r\xd3"\x9d\\,&\xac\x9dX\x95^\xbe\xa5\x96L\xfb\xe9h\x950ftK\xf4\xbe\xa8]_\xc2$&M\x14Q\xcbO[9.\xde$k\xd0t\x8f\xc3\xf2\xb6\xb0\x91\xbdn^A\xcbB|\x9a\xa5\xa7J\xe2\xed\xcdi\xf0!\xad$\x9a\xd8\xf0ah\x12\x96\x9e\x84\xd6\xd6\xef\x1


---

## Learning Outcomes 🎓
1. **AES Encryption**:
   - Understand symmetric encryption using keys and IVs. 🔑
   - Explore block ciphers and CBC mode.

2. **RSA Encryption**:
   - Learn how public-private key pairs are used for secure communication and signatures. 🖋️

3. **Hybrid Cryptography**:
   - Discover the efficiency and security benefits of combining AES and RSA. 🔄

4. **DSM Integration**:
   - Integrate cryptographic operations with enterprise-grade security tools like **Fortanix DSM**. 🛡️

---

## Advanced Tips 💡
1. **Environment Variables for Security**:
   - Use `FORTANIX_API_KEY` to securely store the API key.
   ```bash
   export FORTANIX_API_KEY="<Your API Key>"
   ```

2. **Extensibility**:
   - Extend the script by adding custom workflows in the `Workflows` class. 🛠️

3. **Error Handling**:
   - Utilize the robust logging for debugging and troubleshooting. 📝

---

## License 📜
This project is licensed under the **MIT License**. See the LICENSE file for more details.

---

## Conclusion 🎉
The **Fortanix Secure Communication Script** is a comprehensive demonstration of cryptographic principles in action. By working through the code and examples, you will gain:
- Practical knowledge of AES and RSA.
- An understanding of secure communication workflows.
- Insights into enterprise-grade security practices with Fortanix DSM.


---
## Connect with Me
If you have questions, feedback, or would like to collaborate, feel free to reach out!  
- LinkedIn: [linkedin.com/in/paul-volosen](https://linkedin.com/in/paul-volosen)  
- Email: [paul007ex@gmail.com](mailto:paul007ex@gmail.com)  
