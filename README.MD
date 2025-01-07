
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
[INFO] Encryption successful. Ciphertext: bytearray(b'0\x9f\x91r\xc2\x08\xb8\x05*\xba\xec4;h\xe1\xe6+\xf9\xed\x92\xac\x86-\xa6h\x90\x06*\xce\xaf\x8eO\x7fE\xc9\'\xd1T#I\xed\xfa\x13P\xd0#CMJ|\xa7B%qq\xd5\x7f\x8b\xc68\xef\x02 \xf7\x19\x9f\x87n\x83U\xab\x8a\xc3.\xcdGy\xb4\x10\xf3\xc2\x16\x98\x1ab\xaf\x90\xa4\xba\xd4\xb2\xdc\xb3\x0f\xccR]\xac\xea\xba\x99"\x85\xff\xc8\xf3\x97\xf4N\x91\xb9\xe0\xc4B\xa6\xd3\xc4jji\xfe\xe9>\xe2\x9d\xf3\xf8+q\xc1\xe3\x0b\'\x91r\x01\x8c\xba\xc6d\xbf\xdc6>\xc3\x9d\x0b\x11\xd7\xef\xad5\x98\xd0!\xfe\xeb\xb6l\xac\xa0\xfbG\xa3\x1az\xed+\xdc\xd3\xbb\xa2\xa7\x8a\xd2\xff \xdf\x9a\x97?\xf4D\xb2\xf9\xdcY\\\xe6\x10\x05Q\xe9\xd1\xf2\x86\x9d[\xbe\xe5q\x93\x1c]\xc8\x1d\xcdH\xed\x0e\xa6\xca3\x14\xff\x8b\xef\xb8\x85\x9a\x1d\xfdi\x8a\x96\xe3\xb8\x83*D=^}\xe1\xc4\xc6\xcc\xc1\x0b\x93\x96\x8e\xee\xbb,G/\xb6\x19\r\xed\x85@\xe1\x19\xc5')
[INFO] [Step 4] RSA Encryption Result: Cipher=bytearray(b'0\x9f\x91r\xc2\x08\xb8\x05*\xba\xec4;h\xe1\xe6+\xf9\xed\x92\xac\x86-\xa6h\x90\x06*\xce\xaf\x8eO\x7fE\xc9\'\xd1T#I\xed\xfa\x13P\xd0#CMJ|\xa7B%qq\xd5\x7f\x8b\xc68\xef\x02 \xf7\x19\x9f\x87n\x83U\xab\x8a\xc3.\xcdGy\xb4\x10\xf3\xc2\x16\x98\x1ab\xaf\x90\xa4\xba\xd4\xb2\xdc\xb3\x0f\xccR]\xac\xea\xba\x99"\x85\xff\xc8\xf3\x97\xf4N\x91\xb9\xe0\xc4B\xa6\xd3\xc4jji\xfe\xe9>\xe2\x9d\xf3\xf8+q\xc1\xe3\x0b\'\x91r\x01\x8c\xba\xc6d\xbf\xdc6>\xc3\x9d\x0b\x11\xd7\xef\xad5\x98\xd0!\xfe\xeb\xb6l\xac\xa0\xfbG\xa3\x1az\xed+\xdc\xd3\xbb\xa2\xa7\x8a\xd2\xff \xdf\x9a\x97?\xf4D\xb2\xf9\xdcY\\\xe6\x10\x05Q\xe9\xd1\xf2\x86\x9d[\xbe\xe5q\x93\x1c]\xc8\x1d\xcdH\xed\x0e\xa6\xca3\x14\xff\x8b\xef\xb8\x85\x9a\x1d\xfdi\x8a\x96\xe3\xb8\x83*D=^}\xe1\xc4\xc6\xcc\xc1\x0b\x93\x96\x8e\xee\xbb,G/\xb6\x19\r\xed\x85@\xe1\x19\xc5')
[INFO] Signing data.
[INFO] Retrieving API instance for: digest
[INFO] Retrieving API instance for: signverify
[INFO] Signature generated: bytearray(b'P\xd1\xffZ\xaai20g\x05\x82\xe3!\xc0=\xfbK\nk\'G\x01\xa7\x14\x1e\xdc:\x9c\xac\xb7r\xd3"\x9d\\,&\xac\x9dX\x95^\xbe\xa5\x96L\xfb\xe9h\x950ftK\xf4\xbe\xa8]_\xc2$&M\x14Q\xcbO[9.\xde$k\xd0t\x8f\xc3\xf2\xb6\xb0\x91\xbdn^A\xcbB|\x9a\xa5\xa7J\xe2\xed\xcdi\xf0!\xad$\x9a\xd8\xf0ah\x12\x96\x9e\x84\xd6\xd6\xef\x1f\xad\xbf:N\x0f\xf1\x91\x0e\x96\xda\xad\xc5\x00\xcd\x96\x0eS\xdc\x12\xc3.iW\xfc\xdc$\x86\xcb\xfd\x01\xa6\x02\xd0H\xf6Z\x9bL\xbe\xdfG\xf0\x8c0\xf5&({\xc5\x85\x86^$\xb3\xad< V\xabv\xd8V\x9d\xf4h\xa9\t\xbc\x8e\xab\xa6\'L\x16d\xb1X\x11\x9dL\n\x85\x017\x97m\xd6\x90\xf3\xef\xb3\x97n\xd9\xbf:\xa7&\xa7\x05D\x13/\x80T4"\xf7\x99R,T\xd8\xf4fD\x14\xaa\xadQ\x9e\x07s:8%\x82\'"|d\x94&\x16u\xde\xee\xa4\x9af\x98\xd6/')
[INFO] [Step 5] Signed Data: bytearray(b'P\xd1\xffZ\xaai20g\x05\x82\xe3!\xc0=\xfbK\nk\'G\x01\xa7\x14\x1e\xdc:\x9c\xac\xb7r\xd3"\x9d\\,&\xac\x9dX\x95^\xbe\xa5\x96L\xfb\xe9h\x950ftK\xf4\xbe\xa8]_\xc2$&M\x14Q\xcbO[9.\xde$k\xd0t\x8f\xc3\xf2\xb6\xb0\x91\xbdn^A\xcbB|\x9a\xa5\xa7J\xe2\xed\xcdi\xf0!\xad$\x9a\xd8\xf0ah\x12\x96\x9e\x84\xd6\xd6\xef\x1f\xad\xbf:N\x0f\xf1\x91\x0e\x96\xda\xad\xc5\x00\xcd\x96\x0eS\xdc\x12\xc3.iW\xfc\xdc$\x86\xcb\xfd\x01\xa6\x02\xd0H\xf6Z\x9bL\xbe\xdfG\xf0\x8c0\xf5&({\xc5\x85\x86^$\xb3\xad< V\xabv\xd8V\x9d\xf4h\xa9\t\xbc\x8e\xab\xa6\'L\x16d\xb1X\x11\x9dL\n\x85\x017\x97m\xd6\x90\xf3\xef\xb3\x97n\xd9\xbf:\xa7&\xa7\x05D\x13/\x80T4"\xf7\x99R,T\xd8\xf4fD\x14\xaa\xadQ\x9e\x07s:8%\x82\'"|d\x94&\x16u\xde\xee\xa4\x9af\x98\xd6/')
[INFO] Decrypting data.
[INFO] Retrieving API instance for: crypto
[INFO] Decryption successful. Plaintext: @@@@\n
[INFO] [Step 6] Decrypted Data: @@@@\n
[INFO] Verifying signature.
[INFO] Retrieving API instance for: digest
[INFO] Retrieving API instance for: signverify
[INFO] Signature verification result: True
[INFO] [Step 7] Signature Verification Result: True
[INFO] [Complete] Script execution completed.

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
