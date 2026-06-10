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
    """Deserializes user data with pickle — arbitrary code execution if data is attacker-controlled."""
    return pickle.loads(data)


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
    # 1. Legitimate round-trip with pickle.
    user = {"id": 1, "name": "alice", "role": "user"}
    safe_blob = pickle.dumps(user)
    print("\n[1] Legitimate pickle round-trip")
    print("  Loaded:", load_user_vulnerable(safe_blob))

    # 2. Malicious pickle payload — __reduce__ triggers os.system on load.
    malicious_blob = pickle.dumps(_MaliciousPayload())
    print("\n[2] Malicious pickle payload (vulnerable path)")
    load_user_vulnerable(malicious_blob)

    # 3. Same malicious blob fed to the secure JSON loader — rejected.
    print("\n[3] Same blob against JSON loader (secure path)")
    try:
        load_user_secure(malicious_blob)
    except Exception as e:
        print("  Rejected:", e)

    # 4. Legitimate JSON round-trip.
    json_blob = json.dumps(user).encode()
    print("\n[4] Legitimate JSON round-trip")
    print("  Loaded:", load_user_secure(json_blob))


if __name__ == "__main__":
    demo()
