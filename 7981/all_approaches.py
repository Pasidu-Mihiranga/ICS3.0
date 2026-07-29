import struct, numpy as np
from PIL import Image

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

# ===== APPROACH: Extract 2 LSBs per sample =====
print("=== 2-bit LSB extraction ===")
bits2 = ''
for s in samples:
    bits2 += str((s & 3) >> 1) + str(s & 1)  # bits 1,0
bytes2 = bytes(int(bits2[i:i+8], 2) for i in range(0, len(bits2) - 7, 8))
block2 = bytes2[:882]  # 2 bits per sample * 441 original = 882 bytes

print(f"2-bit block: {len(block2)} bytes")
print(f"First 100: {block2[:100].hex()}")
# Check for archive signatures
for sig, name in [(b'PK\x03\x04', 'ZIP'), (b'\x1f\x8b\x08', 'GZIP')]:
    if sig in block2:
        print(f"FOUND {name}!")
    else:
        print(f"No {name}")

# Check for text
text2 = ''.join(chr(b) if 32<=b<=126 else '.' for b in block2)
print(f"Text (first 200): {text2[:200]}")

# ===== APPROACH: Extract from upper byte LSB ====
print("\n=== Upper byte LSB ===")
samples_bytes = samples.tobytes()
upper_bits = ''
for i in range(1, len(samples_bytes), 2):
    upper_bits += str(samples_bytes[i] & 1)
upper_bytes = bytes(int(upper_bits[i:i+8], 2) for i in range(0, len(upper_bits) - 7, 8))
print(f"Upper LSB block: {len(upper_bytes)} bytes")
text_u = ''.join(chr(b) if 32<=b<=126 else '.' for b in upper_bytes[:441])
print(f"Text: {text_u[:200]}")

for sig, name in [(b'PK\x03\x04', 'ZIP')]:
    if sig in upper_bytes[:441]:
        print(f"FOUND {name}!")

# ===== APPROACH: Try different bit orderings within LSB ====
print("\n=== Bit ordering variations ===")
orig_bits = ''.join(str(s & 1) for s in samples)

# Little-endian bit order per byte
le_bytes = bytes(int(orig_bits[i:i+8][::-1], 2) for i in range(0, len(orig_bits) - 7, 8))
le_block = le_bytes[:441]
for sig, name in [(b'PK\x03\x04', 'ZIP'), (b'\x1f\x8b\x08', 'GZIP')]:
    if sig in le_block:
        print(f"LE bit order: FOUND {name}!")

# Big-endian bit order (but reversed within each 2-byte sample)
be_bytes = bytes(int(orig_bits[i:i+8], 2) for i in range(0, len(orig_bits) - 7, 8))
# Already done, that's the original

# ===== APPROACH: Every Nth sample only ====
print("\n=== Stride-based LSB ===")
for stride in [2, 3, 5, 441]:
    sub_bits = ''.join(str(s & 1) for i, s in enumerate(samples) if i % stride == 0)
    sub_bytes = bytes(int(sub_bits[i:i+8], 2) for i in range(0, len(sub_bits) - 7, 8))
    block_sub = sub_bytes[:500]
    for sig, name in [(b'PK\x03\x04', 'ZIP'), (b'\x1f\x8b\x08', 'GZIP')]:
        if sig in block_sub:
            print(f"Stride {stride}: FOUND {name} at {block_sub.index(sig)}")
    text_sub = ''.join(chr(b) if 32<=b<=126 else '.' for b in block_sub[:100])
    print(f"Stride {stride}: {text_sub}")

# ===== APPROACH: Convert 441-byte block to hex and look for patterns ====
print("\n=== 441-byte block as hex patterns ===")
block = bytes(int(orig_bits[i:i+8], 2) for i in range(0, 441 * 8, 8))
hex_str = block[:441].hex()
print(f"Block hex ({len(hex_str)} chars): {hex_str[:100]}...")

# Convert hex to ASCII (treat each hex pair as decimal 0-255)
# Maybe there's a pattern where numbers encode letters
print("\n=== Block as decimal values (mod 26 = A-Z) ===")
alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
alpha_text = ''.join(alpha[b % 26] if b % 26 < 26 else '?' for b in block[:100])
print(f"Mod 26: {alpha_text}")

alpha_text_full = ''.join(alpha[b % 26] if b % 26 < 26 else '?' for b in block[:441])
print(f"Full (441 chars): {alpha_text_full}")
# Search for readable words in mod-26 text
import re
words = re.findall(r'[A-Z]{4,}', alpha_text_full)
print(f"Words (>=4 letters): {words[:20]}")

# Try mod 36 (0-9, A-Z)
alnum = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
alnum_text = ''.join(alnum[b % 36] for b in block[:100])
print(f"\nMod 36: {alnum_text}")

# ===== APPROACH: Try to decode as Arecibo-style binary bitmap ====
# Arecibo: 73 rows x 23 columns = 1679 bits, FSK 10bps
# This: maybe different dimensions
# 441 bytes = 3528 bits
# Possible dimensions: 3528 = 2^3 * 3^2 * 7^2 = 8 * 441
# Dimensions: 42x84, 63x56, 28x126, 21x168, 14x252, 8x441, etc.
bits_3528 = ''.join(str(b >> j & 1) for b in block for j in range(8))
for h, w in [(42, 84), (63, 56), (28, 126), (21, 168), (14, 252), (8, 441),
             (49, 72), (36, 98), (56, 63), (84, 42), (126, 28), (168, 21)]:
    if h * w == 3528:
        img_data = np.array([int(b) for b in bits_3528[:h*w]]).reshape((h, w)) * 255
        img = Image.fromarray(img_data.astype(np.uint8))
        img = img.resize((w*4, h*4), Image.NEAREST)
        img.save(f'D:/test/CTF/7981/arecibo_{h}x{w}.png')
        print(f"Arecibo {h}x{w}: saved")
