"""
Insecure Deserialization Demo — educational purposes only.
pickle.loads() on untrusted data executes arbitrary code via __reduce__.
The secure alternative is to never deserialize untrusted bytes with pickle;
use a safe format such as JSON instead.
"""

import json
import os
import pickle


# --- VULNERABLE ---------------------------------------------------------------

def load_user_vulnerable(data: bytes) -> dict:
    """Fixed: deserializes user data with JSON — no code execution possible."""
    return json.loads(data)


# --- SECURE -------------------------------------------------------------------

def load_user_secure(data: bytes) -> dict:
    """Deserializes user data with JSON — no code execution possible."""
    return json.loads(data)


# --- Demo ---------------------------------------------------------------------

class _MaliciousPayload:
    """Pickle calls __reduce__ during deserialization; we exploit that to run a command."""
    def __reduce__(self):
        return (os.system, ("echo '[RCE] arbitrary command executed'",))


def demo() -> None:
    user = {"id": 1, "name": "alice", "role": "user"}
    json_blob = json.dumps(user).encode()

    # 1. Legitimate round-trip — both loaders accept valid JSON.
    print("\n[1] Legitimate JSON round-trip")
    print("  Vulnerable:", load_user_vulnerable(json_blob))
    print("  Secure:    ", load_user_secure(json_blob))

    # 2. Malicious pickle payload rejected by both.
    malicious_blob = pickle.dumps(_MaliciousPayload())
    print("\n[2] Malicious pickle payload")
    for label, fn in [("Vulnerable", load_user_vulnerable), ("Secure", load_user_secure)]:
        try:
            fn(malicious_blob)
            print(f"  {label}: ACCEPTED (should not happen)")
        except Exception as e:
            print(f"  {label}: rejected — {e}")


if __name__ == "__main__":
    demo()
