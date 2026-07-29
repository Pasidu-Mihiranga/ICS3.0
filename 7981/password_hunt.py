import struct, numpy as np

with open('D:/test/CTF/7981/7981/0.wav', 'rb') as f:
    raw = f.read()

pos = 12
while pos < len(raw) - 8:
    chunk_id = raw[pos:pos+4]
    chunk_size = struct.unpack_from('<I', raw, pos+4)[0]
    if chunk_id == b'data':
        audio = raw[pos+8:pos+8+chunk_size]
        break
    pos += 8 + chunk_size

samples = np.frombuffer(audio, dtype=np.int16)
lsb_bits = (samples & 1).astype(np.uint8)
padded = np.pad(lsb_bits, (0, 8 - len(lsb_bits) % 8) if len(lsb_bits) % 8 else (0, 0))
lsb_bytes = np.packbits(padded).tobytes()
lsb_bytes = lsb_bytes[:len(lsb_bits) // 8]
block = lsb_bytes[:441]

# === Try extracting different-length passwords from block ===
for pw_len in [8, 10, 12, 16, 20, 32, 64, 200, 441]:
    pw = block[:pw_len]
    pw_text = ''.join(chr(b) if 32<=b<=126 else f'\\x{b:02x}' for b in pw)
    print(f"First {pw_len} bytes as password: {pw_text}")
    print(f"  Hex: {pw.hex()}")

# === Try using the block bytes as indices into alphabet ===
print("\n=== Block as alphabet indices ===")
# If block bytes are 0-25, map to A-Z
alpha_text = ''.join(chr(ord('A') + (b % 26)) for b in block[:100])
print(f"A-Z: {alpha_text}")

# If block bytes are shifted by some amount
for shift in range(1, 11):
    shifted = bytes((b + shift) % 256 for b in block[:100])
    text = ''.join(chr(b) if 32<=b<=126 else '.' for b in shifted)
    readable = sum(1 for b in shifted if 32<=b<=126)
    print(f"Shift +{shift}: readable={readable}: {text[:60]}")

# === Try Vigenere or XOR with "STAGONAGRAPHY" ===
key = b'STAGONAGRAPHY'
xored = bytes(block[i] ^ key[i % len(key)] for i in range(len(block)))
xor_text = ''.join(chr(b) if 32<=b<=126 else '.' for b in xored[:100])
print(f"\nXOR with 'STAGONAGRAPHY': {xor_text[:100]}")
print(f"Readable: {sum(1 for b in xored if 32<=b<=126)}/441")

# Try with "stagonagraphy"
key_lower = b'stagonagraphy'
xored2 = bytes(block[i] ^ key_lower[i % len(key_lower)] for i in range(len(block)))
xor_text2 = ''.join(chr(b) if 32<=b<=126 else '.' for b in xored2[:100])
print(f"XOR with 'stagonagraphy': {xor_text2[:100]}")
print(f"Readable: {sum(1 for b in xored2 if 32<=b<=126)}/441")

# === Check if the block is a known hash ===
import hashlib
print(f"\nBlock MD5: {hashlib.md5(block).hexdigest()}")
print(f"Block SHA1: {hashlib.sha1(block).hexdigest()}")
print(f"Block SHA256: {hashlib.sha256(block).hexdigest()}")

# === Try interpreting as a simple numeric password ===
# Maybe the password is the decimal representation of the block values as one big number
big_num = int.from_bytes(block, 'big')
print(f"\nBlock as big-endian integer: {big_num}")
print(f"Block as integer (first 50 digits): {str(big_num)[:50]}")

# === Check if the block encodes a flag format ===
for fmt_prefix in ['iCS{', 'ICS{', 'flag{', 'FLAG{']:
    for i in range(len(block) - len(fmt_prefix)):
        if all(block[i+j] == ord(fmt_prefix[j]) for j in range(len(fmt_prefix))):
            end = block.find(b'}', i)
            if end != -1:
                print(f"\nRAW FLAG FOUND: {block[i:end+1].decode()}")

# === The password might be hidden in byte differences ===
# XOR adjacent bytes
adj_xor = bytes(block[i] ^ block[i+1] for i in range(440))
adj_text = ''.join(chr(b) if 32<=b<=126 else '.' for b in adj_xor[:100])
print(f"\nAdjacent XOR: readable={sum(1 for b in adj_xor if 32<=b<=126)}/440: {adj_text[:80]}")

# XOR with block reversed
rev_block = block[::-1]
rev_xor = bytes(block[i] ^ rev_block[i] for i in range(441))
rev_text = ''.join(chr(b) if 32<=b<=126 else '.' for b in rev_xor[:100])
print(f"Reverse XOR: readable={sum(1 for b in rev_xor if 32<=b<=126)}/441: {rev_text[:80]}")
