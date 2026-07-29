import struct, numpy as np, base64

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

# ===== 1. Base64 decode from 6-bit grouped bits =====
bits_3528 = lsb_bits[:441*8]
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
b64_chars = []
for i in range(0, len(bits_3528), 6):
    if i + 6 <= len(bits_3528):
        val = int(bits_3528[i:i+6], 2)
        b64_chars.append(alphabet[val])
b64_string = ''.join(b64_chars)
print(f"6-bit base64 ({len(b64_string)} chars): {b64_string}")

# Decode as standard base64
try:
    decoded = base64.b64decode(b64_string)
    print(f"Decoded: {len(decoded)} bytes")
    print(f"Hex: {decoded[:100].hex()}")
    print(f"Text: {''.join(chr(b) if 32<=b<=126 else '.' for b in decoded[:200])}")
    
    # Save decoded data
    with open('D:/test/CTF/7981/decoded_b64.bin', 'wb') as f:
        f.write(decoded)
    print("Saved to decoded_b64.bin")
    
    # Check for flag
    for pat in [b'iCS{', b'ICS{', b'flag{', b'FLAG{', b'CTF{']:
        if pat in decoded:
            idx = decoded.index(pat)
            end = decoded.find(b'}', idx)
            if end != -1:
                print(f"FLAG: {decoded[idx:end+1].decode()}")
except Exception as e:
    print(f"Base64 decode error: {e}")

# ===== 2. XOR with 0xFF and search for flag =====
print("\n=== XOR 0xFF full block ===")
xored = bytes(b ^ 0xFF for b in block)
x_text = ''.join(chr(b) if 32<=b<=126 else '.' for b in xored)
print(f"Full text: {x_text}")

for pat in ['iCS{', 'ICS{', 'flag{', 'FLAG{', '{', '}']:
    for i in range(len(x_text)):
        if x_text[i:i+len(pat)] == pat:
            print(f"  '{pat}' at position {i}: ...{x_text[max(0,i-10):i+50]}...")

# ===== 3. Try XOR with various single-byte keys =====
print("\n=== XOR key search ===")
for key_byte in range(256):
    xored = bytes(b ^ key_byte for b in block)
    x_text = b''.join(bytes([b]) if 32<=b<=126 else b'.' for b in xored).decode('ascii')
    for pat in ['ICS{', 'iCS{', 'flag{', '{']:
        if pat in x_text:
            idx = x_text.index(pat)
            print(f"  Key 0x{key_byte:02x}: found '{pat}' at pos {idx}")

# ===== 4. Check if block itself can be base64 decoded directly =====
print("\n=== Direct base64 decode of block ===")
try:
    # The block has non-base64 chars, so skip this
    block_text = block.decode('ascii', errors='ignore')
    b64_clean = ''.join(c for c in block_text if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    print(f"Base64 chars only: {b64_clean[:100]}")
    decoded2 = base64.b64decode(b64_clean)
    print(f"Decoded: {decoded2[:50].hex()}")
except Exception as e:
    print(f"Error: {e}")

# ===== 5. Try the 441 bytes as binary image but with thresholding =====
from PIL import Image
pixels = np.frombuffer(block, dtype=np.uint8).reshape((21, 21))
# Try binary threshold at 128
binary = (pixels > 128).astype(np.uint8) * 255
img = Image.fromarray(binary, mode='L')
img = img.resize((210, 210), Image.NEAREST)
img.save('D:/test/CTF/7981/block_binary.png')

# Try inverting
binary_inv = 255 - binary
img_inv = Image.fromarray(binary_inv, mode='L')
img_inv = img_inv.resize((210, 210), Image.NEAREST)
img_inv.save('D:/test/CTF/7981/block_binary_inv.png')

# Original with full range
img_full = Image.fromarray(pixels, mode='L')
img_full = img_full.resize((210, 210), Image.NEAREST)
img_full.save('D:/test/CTF/7981/block_full.png')

print("21x21 images saved")
