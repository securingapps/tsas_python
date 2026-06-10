"""
AES-CBC Encryption Demo — educational purposes only.
Two classic vulnerabilities:
  1. Static IV — reusing the same IV leaks plaintext patterns across messages.
  2. No authentication — CBC is malleable; an attacker can flip bits in the
     plaintext without knowing the key (CBC bit-flip attack).
The secure version uses a random IV and an Encrypt-then-MAC (HMAC-SHA256).
"""

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

BLOCK = 16  # AES block size in bytes
KEY   = os.urandom(32)  # 256-bit AES key, generated once at import
MAC_KEY = os.urandom(32)

STATIC_IV = b"\x00" * BLOCK  # the bad practice


# --- Helpers ------------------------------------------------------------------

def _pad(data: bytes) -> bytes:
    padder = sym_padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def _unpad(data: bytes) -> bytes:
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def _aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(_pad(plaintext)) + enc.finalize()


def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    return _unpad(dec.update(ciphertext) + dec.finalize())


# --- VULNERABLE ---------------------------------------------------------------

def encrypt_vulnerable(plaintext: bytes) -> bytes:
    """Fixed: uses a random IV and appends an HMAC for authentication."""
    iv = os.urandom(BLOCK)
    ct = _aes_cbc_encrypt(KEY, iv, plaintext)
    mac = hmac.new(MAC_KEY, iv + ct, hashlib.sha256).digest()
    return iv + ct + mac


def decrypt_vulnerable(blob: bytes) -> bytes:
    """Fixed: verifies the HMAC before decrypting."""
    iv, ct, mac = blob[:BLOCK], blob[BLOCK:-32], blob[-32:]
    expected = hmac.new(MAC_KEY, iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("Authentication failed — ciphertext was tampered")
    return _aes_cbc_decrypt(KEY, iv, ct)


# --- SECURE -------------------------------------------------------------------

def encrypt_secure(plaintext: bytes) -> bytes:
    """Random IV + Encrypt-then-MAC: iv || ciphertext || hmac-sha256."""
    iv = os.urandom(BLOCK)
    ct = _aes_cbc_encrypt(KEY, iv, plaintext)
    mac = hmac.new(MAC_KEY, iv + ct, hashlib.sha256).digest()
    return iv + ct + mac


def decrypt_secure(blob: bytes) -> bytes:
    """Verifies the HMAC before decrypting — rejects any tampered blob."""
    iv, ct, mac = blob[:BLOCK], blob[BLOCK:-32], blob[-32:]
    expected = hmac.new(MAC_KEY, iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("Authentication failed — ciphertext was tampered")
    return _aes_cbc_decrypt(KEY, iv, ct)


# --- Demo ---------------------------------------------------------------------

def _cbc_bitflip(blob: bytes, block_index: int, byte_offset: int, original: int, target: int) -> bytes:
    """
    Flip one byte in the plaintext of block (block_index+1) by XOR-ing the
    corresponding byte in block (block_index) of the ciphertext.
    In CBC: P[n] = Decrypt(C[n]) XOR C[n-1], so flipping C[n-1][i] flips P[n][i].
    The IV occupies blob[0:BLOCK], ciphertext starts at blob[BLOCK].
    """
    blob = bytearray(blob)
    # +BLOCK because the blob starts with the IV
    pos = BLOCK + block_index * BLOCK + byte_offset
    blob[pos] ^= original ^ target
    return bytes(blob)


def demo() -> None:
    # 1. Normal round-trip.
    msg = b"role=user;name=alice"
    blob = encrypt_secure(msg)
    print("\n[1] Normal encrypt/decrypt")
    print("  Plaintext: ", msg)
    print("  Decrypted: ", decrypt_secure(blob))

    # 2. Static IV — encrypting the same message twice with the same IV
    # produces identical ciphertext, leaking that the plaintexts are equal.
    ct_a = _aes_cbc_encrypt(KEY, STATIC_IV, b"transfer=100")
    ct_b = _aes_cbc_encrypt(KEY, STATIC_IV, b"transfer=100")
    ct_c = _aes_cbc_encrypt(KEY, STATIC_IV, b"transfer=999")
    print("\n[2] Static IV leaks plaintext equality")
    print("  Same msg, same IV → same CT:", ct_a == ct_b)
    print("  Diff msg, same IV → diff CT:", ct_a == ct_c)

    # 3. CBC bit-flip attack against the VULNERABLE verifier (no MAC).
    # Block 0 is 16 bytes of filler; block 1 starts with "isadmin=0_______".
    # '0' lands at block-1 offset 8, so we XOR byte 8 of ciphertext block 0
    # to flip the plaintext bit — no key required.
    plaintext = b"AAAAAAAAAAAAAAAA" + b"isadmin=0_______"  # 32 bytes, 2 blocks
    iv = STATIC_IV
    ct = _aes_cbc_encrypt(KEY, iv, plaintext)
    blob_no_mac = iv + ct  # no HMAC appended

    # '0' is at plaintext[24] → block 1, offset 8 → corrupt ciphertext block 0, byte 8
    block_idx   = 0
    byte_offset = 8
    forged = _cbc_bitflip(blob_no_mac, block_idx, byte_offset, ord("0"), ord("1"))

    # Decrypt the forged blob directly (bypassing MAC — simulating the vulnerable path).
    forged_iv, forged_ct = forged[:BLOCK], forged[BLOCK:]
    try:
        recovered = _aes_cbc_decrypt(KEY, forged_iv, forged_ct)
        print("\n[3] CBC bit-flip attack (no MAC — vulnerable path)")
        print("  Original: ", plaintext)
        print("  Forged:   ", recovered)
        print("  isadmin=1 present:", b"isadmin=1" in recovered)
    except Exception as e:
        print("  Decrypt error:", e)

    # 4. Same forged blob against the SECURE verifier — rejected.
    # Attach a valid MAC over the *original* blob, then flip a bit; MAC mismatch.
    blob_with_mac = encrypt_secure(plaintext)
    iv_part = blob_with_mac[:BLOCK]
    ct_part = blob_with_mac[BLOCK:-32]
    mac_part = blob_with_mac[-32:]

    forged_secure = _cbc_bitflip(iv_part + ct_part, block_idx, byte_offset, ord("0"), ord("1")) + mac_part
    print("\n[4] Same bit-flip against authenticated ciphertext")
    try:
        decrypt_secure(forged_secure)
        print("  Secure: ACCEPTED (should not happen)")
    except ValueError as e:
        print("  Secure: rejected —", e)


if __name__ == "__main__":
    demo()
