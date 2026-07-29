"""Decrypt the DCLIC-V1 license record from the Frostline Ledger API image."""
import hashlib
import json
from Crypto.Cipher import AES
from Crypto.Util import Counter

HEADER = b"DCLIC-V1\x00"
LICENSE_PATH = "extracted/9865adf9b59b7a9d4bf6d7137172856ad478af134c21e46731697f40c5e0bbae/app/license.dat"

# Recovery fragments recovered from:
#   LEFT  — fragment-a.txt (deleted via whiteout, still in layer 5c959ef4)
#   RIGHT — ENV RECOVERY_FRAGMENT_B=r3m3mb3r (Docker history, cleared in later layer)
LEFT = "1m4g3_l4y3r5_"
RIGHT = "r3m3mb3r"


def decrypt_license(filepath: str, left: str, right: str):
    blob = open(filepath, "rb").read()
    if not blob.startswith(HEADER):
        raise ValueError("unsupported record")

    counter = blob[9:25]           # 16-byte AES-CTR counter
    payload = blob[25:]            # encrypted body

    key = hashlib.sha256((left + right).encode("utf-8")).digest()
    ctr = Counter.new(128, initial_value=int.from_bytes(counter, "big"))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    plain = cipher.decrypt(payload)
    return json.loads(plain.decode("utf-8"))


if __name__ == "__main__":
    result = decrypt_license(LICENSE_PATH, LEFT, RIGHT)
    print(json.dumps(result, indent=2))
    print(f"\nFlag: {result['flag']}")
