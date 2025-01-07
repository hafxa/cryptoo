# AES Implementation in Python

This project is a **work in progress** implementation of the Advanced Encryption Standard (AES) in Python. It currently supports three block cipher modes:

- **ECB (Electronic Codebook)**
- **CBC (Cipher Block Chaining)**
- **CTR (Counter)**

My goal is to further expand this project by improving its functionality, optimizing the code, and adding more features such as:

- Additional block cipher modes (e.g., GCM, OFB, CFB)
- Support for larger key sizes (e.g., 192-bit, 256-bit)
- Detailed error handling and validation
- Unit tests for better reliability

## Usage

### General Syntax

```bash
python aes.py <input> <key> <iv/counter> -e|-d --mode <mode>
```

- `<input>`: The plaintext/ciphertext to be processed (hexadecimal format)
- `<key>`: The encryption/decryption key (128-bit, 32 hexadecimal characters)
- `<iv/counter>`: Initialization vector for CBC mode or counter for CTR mode (hexadecimal format)
- `-e|--encrypt`: Flag to indicate encryption mode
- `-d|--decrypt`: Flag to indicate decryption mode
- `--mode`: Specifies the block cipher mode (ecb, cbc, ctr)

### Examples

#### **ECB Mode**
- Encrypt:
  ```bash
  python aes.py "00112233445566778899aabbccddeeff" "000102030405060708090a0b0c0d0e0f" -e --mode ecb
  ```

- Decrypt:
  ```bash
  python aes.py "69c4e0d86a7b0430d8cdb78070b4c55a" "000102030405060708090a0b0c0d0e0f" -d --mode ecb
  ```

#### **CBC Mode**
- Encrypt:
  ```bash
  python aes.py "00112233445566778899aabbccddeeff" "000102030405060708090a0b0c0d0e0f" "101112131415161718191a1b1c1d1e1f" -e --mode cbc
  ```

- Decrypt:
  ```bash
  python aes.py "7649abac8119b246cee98e9b12e9197d" "000102030405060708090a0b0c0d0e0f" "101112131415161718191a1b1c1d1e1f" -d --mode cbc
  ```

#### **CTR Mode**
- Encrypt:
  ```bash
  python aes.py "00112233445566778899aabbccddeeff" "000102030405060708090a0b0c0d0e0f" "00000000000000000000000000000001" -e --mode ctr
  ```

- Decrypt:
  ```bash
  python aes.py "874d6191b620e3261bef6864990db6ce" "000102030405060708090a0b0c0d0e0f" "00000000000000000000000000000001" -d --mode ctr
  ```

### Notes
- The key length must be exactly 128 bits (32 hexadecimal characters).
- Ensure the input data is padded for modes that require block alignment (e.g., CBC).
- The initialization vector (IV) or counter must be provided for CBC and CTR modes, respectively.

## Future Plans

- Adding a user-friendly interface (e.g., CLI enhancements or a GUI)
- Implementing real-time encryption and decryption for files
- Providing comprehensive documentation and examples

## Contributions

Feel free to fork the repository and submit pull requests. Suggestions, bug reports, and feature requests are always welcome.

## Disclaimer

This project is for educational purposes only. Do not use this implementation for production-level encryption, as it may lack essential security features and optimizations.

