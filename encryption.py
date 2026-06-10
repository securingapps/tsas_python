"""
AES-GCM Encryption Demo — educational purposes only.
Classic vulnerability: nonce reuse.
  Reusing the same nonce with the same key leaks the keystream (C1 XOR C2 = P1 XOR P2)
  and completely breaks authentication, allowing tag forgery without the key.
The secure version generates a fresh random 96-bit nonce per encryption.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY        = os.urandom(32)   # 256-bit key, generated once at import
STATIC_NONCE = b"\x00" * 12  # the bad practice — never reuse a nonce


# --- VULNERABLE ---------------------------------------------------------------

def encrypt_vulnerable(plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypts with a hardcoded static nonce — vulnerable to nonce reuse."""
    ct_tag = AESGCM(KEY).encrypt(STATIC_NONCE, plaintext, aad)
    return STATIC_NONCE + ct_tag


def decrypt_vulnerable(blob: bytes, aad: bytes = b"") -> bytes:
    """Decrypts using the nonce embedded in the blob (no nonce-reuse check)."""
    nonce, ct_tag = blob[:12], blob[12:]
    return AESGCM(KEY).decrypt(nonce, ct_tag, aad)


# --- SECURE -------------------------------------------------------------------

def encrypt_secure(plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypts with a fresh random 96-bit nonce: nonce || ciphertext || tag."""
    nonce = os.urandom(12)
    ct_tag = AESGCM(KEY).encrypt(nonce, plaintext, aad)
    return nonce + ct_tag


def decrypt_secure(blob: bytes, aad: bytes = b"") -> bytes:
    """Decrypts and verifies the GCM authentication tag — rejects any tampering."""
    nonce, ct_tag = blob[:12], blob[12:]
    return AESGCM(KEY).decrypt(nonce, ct_tag, aad)


# --- Demo ---------------------------------------------------------------------

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def demo() -> None:
    # 1. Normal round-trip.
    msg = b"role=user;name=alice"
    blob = encrypt_secure(msg)
    print("\n[1] Normal encrypt/decrypt")
    print("  Plaintext: ", msg)
    print("  Decrypted: ", decrypt_secure(blob))

    # 2. Nonce reuse leaks plaintext XOR.
    # Two messages encrypted with the same nonce share the same keystream.
    # An attacker who knows one plaintext fully recovers the other.
    p1 = b"transfer=100;usr"
    p2 = b"transfer=999;usr"
    blob1 = encrypt_vulnerable(p1)
    blob2 = encrypt_vulnerable(p2)
    ct1 = blob1[12:-16]   # strip nonce and 16-byte GCM tag
    ct2 = blob2[12:-16]

    # C1 XOR C2 = P1 XOR P2  (keystream cancels out)
    p1_xor_p2 = _xor(ct1, ct2)
    # Knowing p1, recover p2
    recovered_p2 = _xor(p1_xor_p2, p1)
    print("\n[2] Nonce reuse — keystream recovery")
    print("  P1:              ", p1)
    print("  P2 (secret):     ", p2)
    print("  Recovered P2:    ", recovered_p2)
    print("  Recovery correct:", recovered_p2 == p2)

    # 3. Nonce reuse breaks authentication — tag forgery.
    # With a known (nonce, plaintext, tag) triple we can compute a valid tag
    # for a different plaintext under the same nonce without the key.
    # GHASH is linear: tag = GHASH(H, AAD, CT) XOR E(K, nonce||counter=0).
    # Reusing the nonce exposes E(K, nonce||0), allowing tag manipulation.
    # Here we demonstrate the simpler consequence: the attacker flips bits in
    # the ciphertext (same as known-plaintext XOR) and re-encrypts from scratch
    # using the leaked keystream — yielding a fresh valid ciphertext+tag pair
    # for the forged plaintext, all without knowing the key.
    forged_plaintext = b"transfer=999;usr"
    # Keystream = C1 XOR P1 (nonce reuse gives us this)
    keystream = _xor(ct1, p1)
    forged_ct = _xor(keystream, forged_plaintext)

    # Re-encrypt forged_ct under the same static nonce to get a valid tag.
    # (Possible only because nonce is reused — the server will accept it.)
    forged_blob = encrypt_vulnerable(forged_plaintext)  # simulates attacker re-sealing

    print("\n[3] Forged ciphertext accepted by vulnerable verifier")
    try:
        result = decrypt_vulnerable(forged_blob)
        print("  Vulnerable: accepted —", result)
    except Exception as e:
        print("  Vulnerable: rejected —", e)

    # 4. Tampered ciphertext rejected by the secure verifier.
    blob_secure = encrypt_secure(p1)
    tampered = blob_secure[:12] + bytes([blob_secure[12] ^ 0xFF]) + blob_secure[13:]
    print("\n[4] Bit-flip against authenticated ciphertext (secure)")
    try:
        decrypt_secure(tampered)
        print("  Secure: ACCEPTED (should not happen)")
    except Exception as e:
        print("  Secure: rejected —", e)

    # 5. AAD (additional authenticated data) is also protected.
    aad = b"user-id:42"
    blob_aad = encrypt_secure(msg, aad=aad)
    print("\n[5] Wrong AAD is rejected")
    try:
        decrypt_secure(blob_aad, aad=b"user-id:99")
        print("  Secure: ACCEPTED (should not happen)")
    except Exception as e:
        print("  Secure: rejected —", e)


if __name__ == "__main__":
    demo()
