import struct, numpy as np, re
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
print(f"Samples: {len(samples)}")

# Fast numpy-based LSB extraction
lsb_bits = (samples & 1).astype(np.uint8)
print(f"LSB extracted: {len(lsb_bits)} bits")

# Pack bits to bytes (np.packbits)
padded = np.pad(lsb_bits, (0, 8 - len(lsb_bits) % 8) if len(lsb_bits) % 8 else (0, 0))
lsb_bytes = np.packbits(padded).tobytes()
lsb_bytes = lsb_bytes[:len(lsb_bits) // 8]
print(f"Packed: {len(lsb_bytes)} bytes")

block = lsb_bytes[:441]
print(f"Block: {len(block)} bytes")

# === Hex string as password ===
hex_str = block.hex()
print(f"\nHex string ({len(hex_str)} chars):")
print(f"  {hex_str[:80]}...")

# === Mod 26 (A-Z) ===
alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
alpha_text = ''.join(alpha[b % 26] for b in block)
print(f"\nMod-26 ({len(alpha_text)} chars):")
print(f"  {alpha_text[:80]}")
# Find word-like clusters
words = re.findall(r'[A-Z]{4,}', alpha_text)
print(f"  Words (>=4): {words[:15]}")

# === Mod 36 (alphanumeric) ===
alnum = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
alnum_text = ''.join(alnum[b % 36] for b in block)
print(f"\nMod-36 ({len(alnum_text)} chars):")
print(f"  {alnum_text[:80]}")

# === Try XOR with repeating keys ===
for key_name, key in [("7981", b'\x79\x81'), ("200", b'\xc8'), 
                       ("441", bytes([441%256])), ("Arecibo", b'Arecibo')]:
    key_xor = bytes(b ^ key[i % len(key)] for i, b in enumerate(block[:441]))
    text_xor = ''.join(chr(b) if 32<=b<=126 else '.' for b in key_xor)
    readable = sum(1 for b in key_xor if 32<=b<=126)
    print(f"\nXOR '{key_name}' ({readable} readable): {text_xor[:80]}")

# === Arecibo-style binary bitmap ===
bits_all = np.unpackbits(np.frombuffer(block, dtype=np.uint8))
print(f"\nTotal bits: {len(bits_all)}")

for h, w in [(42, 84), (63, 56), (49, 72), (36, 98), (21, 168), (28, 126)]:
    if h * w == 3528:
        bits_sub = bits_all[:h*w]
        img_data = (bits_sub.reshape((h, w)) * 255).astype(np.uint8)
        img = Image.fromarray(img_data)
        img = img.resize((w*5, h*5), Image.NEAREST)
        img.save(f'D:/test/CTF/7981/arecibo_{h}x{w}.png')
        print(f"Saved {h}x{w}")

# === Also: 21x21 as 8-bit depth image, try QR-like detection ===
pixels = np.frombuffer(block, dtype=np.uint8).reshape((21, 21))
# Save scaled versions at different thresholds
for thresh in [64, 96, 128, 160, 192]:
    binary = (pixels > thresh).astype(np.uint8) * 255
    img = Image.fromarray(binary)
    img = img.resize((210, 210), Image.NEAREST)
    img.save(f'D:/test/CTF/7981/block_thresh{thresh}.png')

# Save original scaled
img_orig = Image.fromarray(pixels)
img_orig = img_orig.resize((210, 210), Image.NEAREST)
img_orig.save('D:/test/CTF/7981/block_orig.png')

print("\nImages saved. Check D:/test/CTF/7981/ for PNG files.")
