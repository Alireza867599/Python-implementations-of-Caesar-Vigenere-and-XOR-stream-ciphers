"""
HW1: Substitution Ciphers & Stream Ciphers
Run: python3 hw.py

Tasks:
1) Caesar cipher: encrypt, decrypt, brute-force, frequency analysis
2) Vigenère cipher: encrypt, decrypt
3) Stream cipher XOR (bytes) + keystream reuse demo
"""

import string
from collections import Counter

ALPHABET = string.ascii_uppercase


# ----------------------------
# Task 1: Caesar Cipher
# ----------------------------

def caesar_encrypt(plaintext: str, k: int) -> str:
    """
    Encrypt using Caesar shift (0<=k<26).
    Keep letters A-Z, preserve spaces, ignore other chars or keep them as-is (your choice).
    """
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shifted = (ord(ch) - base + k) % 26
            result.append(chr(base + shifted))
        else:
            # spaces and any other characters are kept unchanged
            result.append(ch)
    return "".join(result)


def caesar_decrypt(ciphertext: str, k: int) -> str:
    """Decrypt Caesar by shifting backward."""
    return caesar_encrypt(ciphertext, -k % 26)


def caesar_bruteforce(ciphertext: str):
    """
    Try all keys 0..25 and return a list of (k, candidate_plaintext).
    """
    return [(k, caesar_decrypt(ciphertext, k)) for k in range(26)]


def letter_frequency(text: str):
    """
    Return a dict of frequency (normalized) of letters A-Z in text.
    Ignore non-letters.
    """
    letters = [ch.upper() for ch in text if ch.isalpha()]
    total = len(letters)
    counts = Counter(letters)
    if total == 0:
        return {letter: 0.0 for letter in ALPHABET}
    return {letter: counts.get(letter, 0) / total for letter in ALPHABET}


# ----------------------------
# Task 2: Vigenère Cipher
# ----------------------------

def vigenere_encrypt(plaintext: str, key: str) -> str:
    """
    Vigenère encryption:
    Ci = (Pi + Ki) mod 26
    Preserve spaces.
    """
    key = key.upper()
    result = []
    ki = 0
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            k = ord(key[ki % len(key)]) - ord('A')
            shifted = (ord(ch) - base + k) % 26
            result.append(chr(base + shifted))
            ki += 1
        else:
            result.append(ch)
    return "".join(result)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Vigenère decryption."""
    key = key.upper()
    result = []
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            k = ord(key[ki % len(key)]) - ord('A')
            shifted = (ord(ch) - base - k) % 26
            result.append(chr(base + shifted))
            ki += 1
        else:
            result.append(ch)
    return "".join(result)


# ----------------------------
# Task 3: Stream cipher XOR
# ----------------------------

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    assert len(b1) == len(b2), "xor_bytes requires equal-length inputs"
    return bytes(x ^ y for x, y in zip(b1, b2))


def stream_encrypt_ascii(plaintext: str, keystream: str) -> bytes:
    """
    Encrypt ASCII plaintext with ASCII keystream using XOR, return ciphertext bytes.
    Assumes same length.
    """
    p_bytes = plaintext.encode("ascii")
    k_bytes = keystream.encode("ascii")
    return xor_bytes(p_bytes, k_bytes)


def stream_decrypt_ascii(cipher_bytes: bytes, keystream: str) -> str:
    """Decrypt XOR stream cipher back to ASCII plaintext."""
    k_bytes = keystream.encode("ascii")
    p_bytes = xor_bytes(cipher_bytes, k_bytes)
    return p_bytes.decode("ascii")


def demo_keystream_reuse(p1: str, p2: str, keystream: str):
    """
    Show why reusing keystream is dangerous.
    Compute c1 = p1 xor k, c2 = p2 xor k, then show c1 xor c2 = p1 xor p2.
    Return (c1, c2, c1_xor_c2, p1_xor_p2).
    """
    c1 = stream_encrypt_ascii(p1, keystream)
    c2 = stream_encrypt_ascii(p2, keystream)
    c1_xor_c2 = xor_bytes(c1, c2)
    p1_xor_p2 = xor_bytes(p1.encode("ascii"), p2.encode("ascii"))
    return c1, c2, c1_xor_c2, p1_xor_p2


def main():
    # === Task 1 Tests ===
    print("=" * 60)
    print("Task 1: Caesar Cipher")
    print("=" * 60)
    pt1 = "SECURITY AND PRIVACY"
    k1 = 7
    ct1 = caesar_encrypt(pt1, k1)
    print(f"Plaintext : {pt1}")
    print(f"Key (k)   : {k1}")
    print(f"Encrypted : {ct1}")

    dec1 = caesar_decrypt(ct1, k1)
    print(f"Decrypted : {dec1}")
    print(f"Round-trip OK: {dec1 == pt1}")

    print("\nBrute-force attack (all 26 keys):")
    for k, candidate in caesar_bruteforce(ct1):
        marker = "  <-- likely plaintext" if candidate == pt1 else ""
        print(f"  k={k:2d}: {candidate}{marker}")

    print("\nFrequency analysis of the ciphertext:")
    freqs = letter_frequency(ct1)
    for letter, freq in sorted(freqs.items(), key=lambda x: -x[1]):
        if freq > 0:
            print(f"  {letter}: {freq:.3f}")

    # === Task 2 Tests ===
    print("\n" + "=" * 60)
    print("Task 2: Vigenere Cipher")
    print("=" * 60)
    pt2 = "KNOWLEDGE IS POWER"
    key2 = "CRYPTO"
    ct2 = vigenere_encrypt(pt2, key2)
    print(f"Plaintext : {pt2}")
    print(f"Key       : {key2}")
    print(f"Encrypted : {ct2}")

    dec2 = vigenere_decrypt(ct2, key2)
    print(f"Decrypted : {dec2}")
    print(f"Round-trip OK: {dec2 == pt2}")

    # === Task 3 Tests ===
    print("\n" + "=" * 60)
    print("Task 3: Stream Cipher (XOR) + Keystream Reuse Attack")
    print("=" * 60)
    p1 = "ATTACKATDAWN"
    ks = "XMCKLXMCKLXM"
    p2 = "DEFENDATNOON"

    c1_single = stream_encrypt_ascii(p1, ks)
    print(f"p1        : {p1}")
    print(f"keystream : {ks}")
    print(f"c1 (hex)  : {c1_single.hex()}")
    dec_p1 = stream_decrypt_ascii(c1_single, ks)
    print(f"decrypted : {dec_p1}  (round-trip OK: {dec_p1 == p1})")

    print("\nKeystream reuse demo (same keystream used for p1 and p2):")
    c1, c2, c1_xor_c2, p1_xor_p2 = demo_keystream_reuse(p1, p2, ks)
    print(f"p2            : {p2}")
    print(f"c1 (hex)      : {c1.hex()}")
    print(f"c2 (hex)      : {c2.hex()}")
    print(f"c1 xor c2 (hex): {c1_xor_c2.hex()}")
    print(f"p1 xor p2 (hex): {p1_xor_p2.hex()}")
    print(f"c1^c2 == p1^p2 : {c1_xor_c2 == p1_xor_p2}")
    print("\n=> An attacker who intercepts c1 and c2 can compute c1 xor c2 = p1 xor p2")
    print("   without ever knowing the keystream. If p1 (or a crib of it) is guessed,")
    print("   p2 can be recovered directly: p2 = (c1 xor c2) xor p1.")


if __name__ == "__main__":
    main()
