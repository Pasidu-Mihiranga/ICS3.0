#!/usr/bin/env python3
"""
BOS-400 Telegraph Archive - solver.

Reverses the recorder + authentication transforms and strips the terminal's
synchronisation chatter to recover the payload.

Forward process was:
    address -> XOR(hash prefix) -> nibble swap -> stored
So we undo it in reverse: swap nibbles, XOR again, map through the codebook.
"""
import hashlib

recorded_hex = """
2537 9B4C 0B61 8A34 D702 68BA C2F3 BBEB 13B6 5CCC
3A42 29E1 9790 8B78 81F3 4A1B 6006
"""

codebook = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "{}_!@#$%^&*()-=+[]|;:',.<>?/`~ "
)

card_key = "M7KPX9ZL"
auth_material = (card_key + "C0D3").encode()

# Retain the first 16 bytes of SHA-256 (FIPS PUB 180-4).
fingerprint = hashlib.sha256(auth_material).digest()[:16]
recorded = bytes.fromhex(recorded_hex)

# Undo the archive recorder's high/low nibble exchange (self-inverse).
before_recorder = bytes(
    (byte >> 4) | ((byte & 0x0F) << 4)
    for byte in recorded
)

# Undo the authentication XOR gate (self-inverse).
addresses = bytes(
    byte ^ fingerprint[index % len(fingerprint)]
    for index, byte in enumerate(before_recorder)
)

decoded = "".join(codebook[address] for address in addresses)
payload = decoded[8:]  # first 8 chars are synchronisation chatter

print(f"Fingerprint: {fingerprint.hex()}")
print(f"Decoded:     {decoded}")
print(f"Payload:     {payload}")
