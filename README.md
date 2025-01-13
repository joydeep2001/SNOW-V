# SNOW V Encryption/Decryption Implementation

This project is an implementation of the SNOW V stream cipher for encrypting and decrypting large files. The code uses the OpenSSL library to handle key derivation from passwords and includes a basic command-line interface to process files securely. The program supports both encryption and decryption modes.

---

## What is SNOW V?
SNOW V is a stream cipher designed for fast and secure encryption of data streams. It is part of the SNOW family of stream ciphers and offers a balance of high security and performance. SNOW V is commonly used in secure communication protocols, ensuring that transmitted data remains confidential and protected against tampering.

Unlike block ciphers, stream ciphers like SNOW V encrypt data one bit or byte at a time, making them suitable for scenarios where data size may not be a multiple of the block size. This property makes SNOW V an excellent choice for real-time applications and large file encryption.

---

## What Have We Done Here?
In this project, we have:

1. **Implemented the core SNOW V algorithm**: Using the Linear Feedback Shift Register (LFSR) and Finite State Machine (FSM) principles to generate keystreams for encryption.
2. **Integrated OpenSSL functions**: To derive encryption keys from a user-provided password using the PBKDF2 algorithm with HMAC-SHA256.
3. **Created a file encryption/decryption utility**: The program allows users to encrypt or decrypt large files by providing a password. A random salt is used during encryption to enhance security, and the same salt is used during decryption to derive the correct key.
4. **Developed a command-line interface**: The user interacts with the program through a terminal-based menu to choose between encryption, decryption, or exiting the program.

---

## Prerequisites to Run the Code (Ubuntu)
To run this SNOW V encryption/decryption tool on Ubuntu, ensure the following prerequisites are met:

### 🔧 Install OpenSSL
```bash
sudo apt update
sudo apt install openssl libssl-dev
```

### 📂 Compile the Code
Use the `gcc` compiler to compile the code:
```bash
gcc -o snow_v_encryption main.c -lcrypto
```

### ▶️ Run the Program
```bash
./snow_v_encryption
```
Follow the on-screen instructions to encrypt or decrypt a file by providing the file name and a password.

---

## Video Guide for using the code


## File Processing
1. **Encryption**: The program generates a random salt and derives a key from the password using the PBKDF2 algorithm. The input file is processed in blocks of 16KB, and each block is XORed with the generated keystream to produce the encrypted file.
2. **Decryption**: The salt is read from the encrypted file, and the same password is used to derive the decryption key. The keystream is regenerated to XOR with the encrypted data, resulting in the original plaintext.

---

## Conclusion
This project showcases a practical implementation of the SNOW V stream cipher with secure key derivation using OpenSSL. By using this tool, users can securely encrypt and decrypt large files on their Ubuntu systems. The use of a stream cipher ensures efficient processing of data, while the integration of modern cryptographic functions enhances the overall security of the application.

Always remember to use strong passwords and keep them safe to ensure the security of your encrypted files.

