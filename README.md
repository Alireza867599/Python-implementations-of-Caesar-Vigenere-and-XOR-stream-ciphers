# Python-implementations-of-Caesar-Vigenere-and-XOR-stream-ciphers
Python implementation of classical cryptographic algorithms, including Caesar Cipher, Vigenère Cipher, and XOR-based Stream Cipher, with encryption, decryption, brute-force attacks, frequency analysis, and keystream reuse security demonstrations.


# Cryptography Homework 1

**Substitution Ciphers and Stream Ciphers | Hardware Security**

This project contains Python implementations of classical substitution ciphers and a simple XOR-based stream cipher. It demonstrates encryption, decryption, basic cryptanalysis, and the security risks of reusing a keystream.

## Features

### 1. Caesar Cipher
- Encrypt and decrypt text with a shift key.
- Try all 26 keys with a brute-force attack.
- Calculate normalized letter frequencies for ciphertext analysis.

### 2. Vigenère Cipher
- Encrypt and decrypt text with a repeating alphabetic key.
- Preserve spaces and punctuation while processing letters.

### 3. XOR Stream Cipher
- Encrypt and decrypt ASCII text using a same-length keystream.
- Demonstrate why keystream reuse is insecure:

  `C1 XOR C2 = P1 XOR P2`

## Requirements

- Python 3
- No third-party packages (uses Python's standard library)

## How to Run

Download the files and run the completed solution from your terminal:

```bash
python "solution(2).py"
```

On systems where the Python 3 command is `python3`, use:

```bash
python3 "solution(2).py"
```

> **Tip:** You can rename `solution(2).py` to `solution.py` for a cleaner repository. If you do, run `python solution.py` instead.

## Example Results

The completed script demonstrates:

- **Caesar:** `SECURITY AND PRIVACY` encrypted with key `7` becomes `ZLJBYPAF HUK WYPCHJF`.
- **Vigenère:** `KNOWLEDGE IS POWER` encrypted with key `CRYPTO`, then decrypted back to the original text.
- **Stream cipher:** `ATTACKATDAWN` encrypted with keystream `XMCKLXMCKLXM`, then decrypted back to the original text.
- **Keystream reuse:** The program confirms that XORing two ciphertexts created with the same keystream equals XORing their plaintexts (`Match? True`).

## Files

| File | Description |
| --- | --- |
| `solution(2).py` | Completed Python implementation and demonstrations |
| `hw(4).py` | Original Python starter template |
| `تمرین شماره 1.pdf` | Assignment instructions (if sharing is permitted) |

## Educational Note

These ciphers and the fixed-keystream examples are provided for learning and security analysis. They should **not** be used to protect real-world sensitive information.
