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
lsb_bits = ''.join(str(s & 1) for s in samples)
lsb_bytes = bytes(int(lsb_bits[i:i+8], 2) for i in range(0, len(lsb_bits) - 7, 8))
block = lsb_bytes[:441]

# === 21x21 Image ===
print("=== 21x21 Image ===")
for size in [21]:
    pixels = np.frombuffer(block, dtype=np.uint8).reshape((size, size))
    img = Image.fromarray(pixels, mode='L')
    img = img.resize((size*10, size*10), Image.NEAREST)
    img.save(f'D:/test/CTF/7981/block_{size}x{size}.png')
    
    # Also print as ASCII art
    print("ASCII art (':' = dark, '#' = light):")
    ascii_map = " .:-=+*#%@"
    for row in pixels:
        line = ''.join(ascii_map[min(int(p) * len(ascii_map) // 256, len(ascii_map)-1)] for p in row)
        print(f"  {line}")

# === Try various XOR keys ===
print("\n=== XOR Analysis ===")
for key_byte in [441 % 256, 7981 % 256, 200, 0x41, 0x55, 0xAA, 0xFF]:
    xored = bytearray(b ^ key_byte for b in block)
    text = ''.join(chr(b) if 32<=b<=126 else '.' for b in xored)
    readable = sum(1 for b in xored if 32<=b<=126)
    print(f"XOR 0x{key_byte:02x}: readable={readable}/{len(block)}: {text[:80]}")

# === Try 441 bytes as different encodings ===
print("\n=== Encoding Analysis ===")

# Try as raw flag
for pattern in [b'iCS{', b'ICS{', b'flag{', b'FLAG{', b'CTF{']:
    if pattern in block:
        idx = block.index(pattern)
        end = block.find(b'}', idx)
        if end != -1:
            print(f"FLAG in raw: {block[idx:end+1].decode()}")

# Try bit-reversed
rev_block_ls = []
for i in range(0, 441 * 8, 8):
    byte_bits = lsb_bits[i:i+8][::-1]
    rev_block_ls.append(int(byte_bits, 2))
rev_block = bytes(rev_block_ls)
rev_text = ''.join(chr(b) if 32<=b<=126 else '.' for b in rev_block)
for sig, name in [(b'PK\x03\x04', 'ZIP')]:
    if sig in rev_block:
        print(f"FOUND {name} in bit-reversed block!")

# Try interpreting bytes as 7-bit ASCII
print("\n=== 7-bit ASCII interpretation ===")
bits_3528 = lsb_bits[:441*8]
chars_7bit = []
for i in range(0, len(bits_3528) - 6, 7):
    val = int(bits_3528[i:i+7], 2)
    if 32 <= val <= 126:
        chars_7bit.append(chr(val))
    else:
        chars_7bit.append('.')
text_7 = ''.join(chars_7bit[:100])
print(f"First 100 chars: {text_7}")

# Try 6-bit encoding (just first 441 bytes worth of bits = 3528 bits)
bits_3528 = lsb_bits[:441*8]
chars_6bit = []
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
for i in range(0, len(bits_3528) - 5, 6):
    val = int(bits_3528[i:i+6], 2)
    if val < 64:
        chars_6bit.append(alphabet[val])
    else:
        chars_6bit.append('?')
text_6 = ''.join(chars_6bit[:100])
print(f"Base64 (6-bit): {text_6}")

# === Try to decode the block as encrypted text ===
# The block might be a passphrase. Let's check common lengths.
print(f"\nBlock size: {len(block)} bytes")
# 441 is close to some common sizes
# Maybe it's a 21x21 QR-like code

# Check if bytes are all unique
unique_bytes = len(set(block))
print(f"Unique bytes: {unique_bytes}/{len(block)}")
print(f"Byte range: min={min(block)}, max={max(block)}")
