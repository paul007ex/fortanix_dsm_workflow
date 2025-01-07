
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

### ⚙️ **Combined AES-RSA Encryption**
Combines the strengths of AES and RSA:
- **Efficiency**: AES is faster and better suited for encrypting large data.
- **Secure Key Exchange**: RSA ensures the secure transmission of the AES key.
- **Signature Verification**: RSA provides data authenticity and integrity.

#### **Combined AES-RSA Workflow**:
1. The **plaintext** is encrypted using AES with a shared AES key and IV. 🛡️
2. The **AES key** is encrypted using the **receiver's RSA public key**.
3. The **plaintext** is signed with the **sender's RSA private key**.
4. The receiver decrypts the AES key with their **RSA private key**, decrypts the ciphertext using AES, and verifies the signature.

---

## Protocol Overview 📡
### Sender-Receiver Flow
1. **Sender** (e.g., John):
   - Encrypts the message with an AES key.
   - Encrypts the AES key with the receiver's RSA public key.
   - Signs the message using their RSA private key.

2. **Receiver** (e.g., Priya):
   - Decrypts the AES key using their RSA private key.
   - Decrypts the ciphertext with the AES key.
   - Verifies the signature using the sender's RSA public key.

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

### Protocol Wireframe: Data Flow Visualization

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
python fortanix_secure_comm_v4.py --api-key <API_KEY> --workflow <aes|rsa|combined> --message <message>
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
[INFO] Starting the script. 🚀
[INFO] Initializing DSM client. 🛡️
[INFO] DSM client configured with the following settings:
  Host: https://apps.smartkey.io 🌐
  Username: ******** 🔑
[INFO] Executing Advanced AES-RSA Combined Workflow. 🔄
[INFO] Encrypting plaintext using AES. 🔐
[INFO] AES Encryption Result: Cipher=********, IV=********
...
[INFO] Script execution completed. ✅
```

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
