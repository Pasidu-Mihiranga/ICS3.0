#!/usr/bin/env python3
"""
The Candidate Who Never Whispered - solver.

Pull the characters at Fibonacci-numbered (1-based) positions out of
private_broadcast.enc, then run the result through a 3-rail Rail Fence decrypt.
"""
from pathlib import Path


def fibonacci_positions(limit):
    """Return zero-based indexes for 1-based Fibonacci positions."""
    positions = []
    first, second = 1, 2
    while first <= limit:
        positions.append(first - 1)
        first, second = second, first + second
    return positions


def rail_fence_decrypt(ciphertext, rails):
    cycle = list(range(rails)) + list(range(rails - 2, 0, -1))
    pattern = [cycle[index % len(cycle)] for index in range(len(ciphertext))]

    row_lengths = [pattern.count(row) for row in range(rails)]

    rows = []
    offset = 0
    for length in row_lengths:
        rows.append(list(ciphertext[offset:offset + length]))
        offset += length

    return "".join(rows[row].pop(0) for row in pattern)


broadcast = Path("private_broadcast.enc").read_text().strip()

positions = fibonacci_positions(len(broadcast))
extracted = "".join(broadcast[index] for index in positions)
plaintext = rail_fence_decrypt(extracted, 3)

print(f"Extracted: {extracted}")
print(f"Decrypted: {plaintext}")
# The event uses the mixed-case prefix iCS, so replace the generic FLAG prefix.
print("Flag:      " + plaintext.replace("FLAG", "iCS", 1))
