import struct
import numpy as np

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

# Extract LSB bits
lsb_bits = ''.join(str(s & 1) for s in samples)
lsb_bytes = bytearray()
for i in range(0, len(lsb_bits) - 7, 8):
    lsb_bytes.append(int(lsb_bits[i:i+8], 2))

# === APPROACH 1: Look for readable text in LSB ===
text = lsb_bytes.decode('ascii', errors='replace')
# Find all readable strings of length > 4
import re
words = re.findall(r'[a-zA-Z0-9_\-\.]{5,}', text)
print("=== Readable strings in LSB (length >= 5) ===")
for w in words[:50]:
    if len(w) > 3:
        print(f"  '{w}' at offset {text.find(w)}")

# === APPROACH 2: Try XOR with various keys ===
keys_to_try = [
    b'\x79\x81',       # "7981" as two bytes
    b'\x79\x81\x00\x00',  # "7981" + 00 00
    b'\xc8',           # 200 (0xC8)
    b'\x00\x00',       # 0 0
    bytes([79, 81]),   # 79, 81
    bytes([200]),      # 200
    b'\x20\x00',       # 200 in ASCII ('2','0','0')
    b'ICS{',           # flag prefix
    b'password',
]

for key in keys_to_try:
    try:
        xored = bytearray()
        for i, b in enumerate(lsb_bytes[:2000]):
            xored.append(b ^ key[i % len(key)])
        # Check for readable text
        xored_text = xored.decode('ascii', errors='replace')
        readable = re.findall(r'[a-zA-Z0-9_\-\.]{5,}', xored_text)
        if readable:
            print(f"\nXOR with {key}: found {len(readable)} readable strings")
            for w in readable[:10]:
                print(f"  '{w}'")
    except:
        pass

# === APPROACH 3: Try different LSB extraction patterns ===
# Extract LSB from every Nth sample
for stride in [2, 3, 4, 5, 10, 79, 81, 200]:
    subset_bits = ''.join(str(samples[i] & 1) for i in range(0, len(samples), stride))
    subset_bytes = bytearray()
    for i in range(0, len(subset_bits) - 7, 8):
        subset_bytes.append(int(subset_bits[i:i+8], 2))
    
    # Check for signatures
    for sig, name in [(b'PK\x03\x04', 'ZIP'), (b'\x1f\x8b', 'GZIP'),
                       (b'BZh', 'BZ2')]:
        idx = subset_bytes.find(sig)
        if idx >= 0:
            print(f"\nStride {stride}: FOUND {name} at {idx} in {len(subset_bytes)} bytes!")

# === APPROACH 4: Try byte-reversal (LSB first = MSB?) ===
# Maybe bits are collected in reverse order per byte
rev_bytes = bytearray()
for i in range(0, len(lsb_bits) - 7, 8):
    byte_bits = lsb_bits[i:i+8]
    rev_bytes.append(int(byte_bits[::-1], 2))

for sig, name in [(b'PK\x03\x04', 'ZIP'), (b'\x1f\x8b', 'GZIP')]:
    idx = rev_bytes.find(sig)
    if idx >= 0:
        print(f"\nReverse bit order: FOUND {name} at {idx}!")

# Check first 100 bytes reversed
print(f"\nFirst 100 bytes (bit-reversed): {rev_bytes[:100].hex()}")

# === APPROACH 5: Try extracting from the 2nd LSB (bit 1) ===
for bit_pos in [1, 2, 3, 14, 15]:
    bits = ''.join(str((s >> bit_pos) & 1) for s in samples)
    b2_bytes = bytearray()
    for i in range(0, len(bits) - 7, 8):
        b2_bytes.append(int(bits[i:i+8], 2))
    
    for sig, name in [(b'PK\x03\x04', 'ZIP'), (b'\x1f\x8b', 'GZIP'), (b'\x89PNG', 'PNG')]:
        idx = b2_bytes.find(sig)
        if idx >= 0:
            print(f"\nBit position {bit_pos}: FOUND {name} at {idx}!")

print("\nDone")
