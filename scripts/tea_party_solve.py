#!/usr/bin/env python3
"""
Invitation to Tea Party - full solve.

alice_tea_table_cipher/ is a substitution table: each subdirectory is named after
one plaintext character, and the 45 JPEGs inside it are the symbols encoding it.
drink_me.txt is a run of SHA-256 digests of those images, 64 hex chars each.

Decoding = sha256(image bytes) -> name of the directory holding that image.

Usage: python tea_party_solve.py [tea_party.zip]
Stdlib only. Reads straight from the archive; nothing is extracted to disk.
"""
import hashlib
import os
import sys
import zipfile

ZIP = sys.argv[1] if len(sys.argv) > 1 else "tea_party.zip"
ROOT = "alice_tea_table_cipher"

with zipfile.ZipFile(ZIP) as z:
    ciphertext = z.read(f"{ROOT}/drink_me.txt").decode().strip()

    # sha256(file bytes) -> parent directory name (the plaintext character)
    table = {}
    for name in (i.filename for i in z.infolist() if i.filename.endswith(".jpg")):
        table[hashlib.sha256(z.read(name)).hexdigest()] = os.path.basename(os.path.dirname(name))

alphabet = sorted(set(table.values()))
print(f"table:      {len(table)} images over {len(alphabet)} characters")
print(f"alphabet:   {''.join(alphabet)}")

# 64 hex chars per record, not the 16 the filenames bait you into
assert len(ciphertext) % 64 == 0, f"ciphertext is {len(ciphertext)} chars, not a multiple of 64"
digests = [ciphertext[i:i + 64] for i in range(0, len(ciphertext), 64)]
print(f"ciphertext: {len(ciphertext)} hex chars -> {len(digests)} records "
      f"({len(set(digests))} unique)")

unresolved = [d for d in digests if d not in table]
if unresolved:
    print(f"WARNING: {len(unresolved)} unresolved records")

flag = "".join(table.get(d, "?") for d in digests)
print(f"\nflag: {flag}")
