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

lsb_bits = ''.join(str(s & 1) for s in samples)
lsb_bytes = bytes(int(lsb_bits[i:i+8], 2) for i in range(0, len(lsb_bits) - 7, 8))

block_size = 441
print(f"LSB total: {len(lsb_bytes)} bytes")
print(f"Blocks of {block_size}: {len(lsb_bytes) // block_size}")

# Extract one block
block = lsb_bytes[:block_size]
print(f"\n=== Block 0 ({len(block)} bytes) ===")
print(f"Hex: {block.hex()}")

# Are all blocks identical?
all_same = True
for i in range(1, min(10, len(lsb_bytes) // block_size)):
    if lsb_bytes[i*block_size:(i+1)*block_size] != block:
        diff_count = sum(1 for a, b in zip(block, lsb_bytes[i*block_size:(i+1)*block_size]) if a != b)
        print(f"Block {i}: DIFFERS from block 0 by {diff_count} bytes")
        all_same = False
        break

if all_same:
    print("All blocks are IDENTICAL!")

# Analyze the block
print(f"\n--- Block content analysis ---")
# Check for text
text = ''.join(chr(b) if 32<=b<=126 else '.' for b in block)
print(f"Printable: {text}")
print(f"Printable chars: {sum(1 for b in block if 32<=b<=126)} / {len(block)}")

# Check for repeating sub-patterns
for sub in [8, 16, 21, 49, 63, 147]:
    if block_size % sub == 0:
        parts = [block[i:i+sub] for i in range(0, block_size, sub)]
        unique = len(set(parts))
        print(f"  Sub={sub}: {len(parts)} parts, {unique} unique")

# Try to read as different formats
import base64
try:
    b64 = base64.b64decode(block)
    print(f"\nBase64 decoded: {len(b64)} bytes: {b64[:50].hex()}")
except:
    print("Not valid base64")

try:
    b32 = base64.b32decode(block)
    print(f"Base32 decoded: {len(b32)} bytes: {b32[:50].hex()}")
except:
    pass

# Try to interpret as XOR or substitution
# Check if XORing with 441 or 7981 reveals text
for key_val, key_name in [(441, '441'), (7981%256, '7981%256'), 
                            (200, '200'), (0x41, '0x41')]:
    xored = bytes(b ^ key_val for b in block)
    x_text = ''.join(chr(b) if 32<=b<=126 else '.' for b in xored)
    print(f"\nXOR with {key_name}:")
    print(f"  {x_text[:80]}")
    # Check for readable words
    import re
    words = re.findall(r'[A-Za-z]{4,}', x_text)
    if words:
        print(f"  Words: {words}")

# Try reversing bit order
rev_bits = ''.join(lsb_bits[i:i+8][::-1] for i in range(0, len(lsb_bits) - 7, 8))
rev_bytes = bytes(int(rev_bits[i:i+8], 2) for i in range(0, len(rev_bits) - 7, 8))
rev_block = rev_bytes[:block_size]
rev_text = ''.join(chr(b) if 32<=b<=126 else '.' for b in rev_block)
print(f"\nBit-reversed block: {rev_text}")
for sig, name in [(b'PK\x03\x04', 'ZIP'), (b'\x1f\x8b\x08', 'GZIP')]:
    if sig in rev_block:
        print(f"  FOUND {name} in bit-reversed!")

# Save the unique block
with open('D:/test/CTF/7981/unique_block.bin', 'wb') as f:
    f.write(block)
print(f"\nUnique block saved to unique_block.bin")
