"""
JWT "none" Algorithm Demo — educational purposes only.
CVE-2015-9235: accepting "none" as a valid algorithm lets an attacker forge
tokens by stripping the signature and setting alg=none in the header.
"""

import base64
import hashlib
import hmac
import json


SECRET = "super-secret-key"


# --- Helpers ------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def create_token(payload: dict) -> str:
    """Create a legitimately signed HS256 JWT."""
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url_encode(json.dumps(payload).encode())
    sig = hmac.new(SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url_encode(sig)}"


# --- VULNERABLE ---------------------------------------------------------------

def verify_vulnerable(token: str) -> dict:
    """Fixed: always verifies with HS256 — ignores the alg field in the header."""
    header_b64, payload_b64, sig_b64 = token.split(".")
    expected = hmac.new(
        SECRET.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(_b64url_decode(sig_b64), expected):
        raise ValueError("Invalid signature")
    return json.loads(_b64url_decode(payload_b64))


# --- SECURE -------------------------------------------------------------------

def verify_secure(token: str) -> dict:
    """Always verifies with HS256 — ignores the alg field in the header."""
    header_b64, payload_b64, sig_b64 = token.split(".")
    expected = hmac.new(
        SECRET.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(_b64url_decode(sig_b64), expected):
        raise ValueError("Invalid signature")
    return json.loads(_b64url_decode(payload_b64))


# --- Demo ---------------------------------------------------------------------

def _forge_none_token(payload: dict) -> str:
    """Craft a token with alg=none and an empty signature."""
    header = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = _b64url_encode(json.dumps(payload).encode())
    return f"{header}.{body}."  # empty signature


def demo() -> None:
    # 1. Normal round-trip — both versions accept a real token.
    legit = create_token({"sub": "alice", "role": "user"})
    print("\n[1] Legitimate HS256 token")
    print("  Token:     ", legit)
    print("  Vulnerable:", verify_vulnerable(legit))
    print("  Secure:    ", verify_secure(legit))

    # 2. Forged none-algorithm token claiming admin role.
    # The attacker strips the signature and sets alg=none; no secret needed.
    forged = _forge_none_token({"sub": "attacker", "role": "admin"})
    print("\n[2] Forged token with alg=none (no secret required)")
    print("  Forged:    ", forged)

    try:
        result = verify_vulnerable(forged)
        print("  Vulnerable (ACCEPTED — role is):", result["role"])
    except ValueError as e:
        print("  Vulnerable: rejected —", e)

    try:
        result = verify_secure(forged)
        print("  Secure (ACCEPTED — role is):", result["role"])
    except ValueError as e:
        print("  Secure:     rejected —", e)

    # 3. Tampered signature on a real HS256 token — both should reject.
    parts = legit.split(".")
    tampered_payload = _b64url_encode(json.dumps({"sub": "alice", "role": "admin"}).encode())
    tampered = f"{parts[0]}.{tampered_payload}.{parts[2]}"
    print("\n[3] Tampered HS256 payload (wrong signature)")
    for label, fn in [("Vulnerable", verify_vulnerable), ("Secure", verify_secure)]:
        try:
            print(f"  {label}: accepted —", fn(tampered))
        except ValueError as e:
            print(f"  {label}: rejected —", e)


if __name__ == "__main__":
    demo()
