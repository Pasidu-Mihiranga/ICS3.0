import struct, numpy as np, zlib
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
lsb_bits = (samples & 1).astype(np.uint8)
padded = np.pad(lsb_bits, (0, 8 - len(lsb_bits) % 8) if len(lsb_bits) % 8 else (0, 0))
lsb_bytes = np.packbits(padded).tobytes()[:len(lsb_bits)//8]
block = lsb_bytes[:441]

# ===== CRITICAL INSIGHT: 441 = 21x21 squares =====
# Each byte = one pixel of a 21x21 image
pixels = np.frombuffer(block, dtype=np.uint8).reshape((21, 21))
print("=== 21x21 Block Pixel Grid ===")
# Print as hex values
for row in pixels:
    print(' '.join(f'{p:02x}' for p in row))

# Also print as 1-bit binary (threshold at 128)
print("\n=== Binary (threshold 128, 1=#, 0=.) ===")
for row in pixels:
    print(''.join('#' if p > 128 else '.' for p in row))

print("\n=== Binary (threshold 64, 1=#, 0=.) ===") 
for row in pixels:
    print(''.join('#' if p > 64 else '.' for p in row))

# Try reading columns
print("\n=== Columns read as ASCII (if bytes >= 32) ===")
for col_idx in range(21):
    col_bytes = pixels[:, col_idx]
    col_text = ''.join(chr(b) if 32<=b<=126 else '.' for b in col_bytes)
    print(f"Col {col_idx:2d}: {col_text}")

# Try reading rows
print("\n=== Rows read as ASCII ===")
for row_idx in range(21):
    row_text = ''.join(chr(b) if 32<=b<=126 else '.' for b in pixels[row_idx])
    print(f"Row {row_idx:2d}: {row_text}")

# ===== Try differential LSB =====
print("\n=== Differential LSB ===")
diff_lsb = (lsb_bits[:-1] ^ lsd_bits[1:]).astype(np.uint8)
diff_padded = np.pad(diff_lsb, (0, 8 - len(diff_lsb) % 8) if len(diff_lsb) % 8 else (0, 0))
diff_bytes = np.packbits(diff_padded).tobytes()[:len(diff_lsb)//8]
diff_block = diff_bytes[:441]
# Check for ZIP
if b'PK\x03\x04' in diff_bytes[:2000]:
    print("FOUND ZIP in diff LSB!")
diff_db_text = ''.join(chr(b) if 32<=b<=126 else '.' for b in diff_block[:100])
print(f"Diff block first 100: {diff_db_text}")

# ===== Try interleaved LSB from both bytes of each sample =====
print("\n=== Dual-byte LSB (per 16-bit sample, low then high byte) ===")
samples_bytes = samples.tobytes()
dual_lsb = np.zeros(len(samples) * 2, dtype=np.uint8)
for i in range(len(samples)):
    dual_lsb[i*2] = samples_bytes[i*2] & 1       # LSB of low byte
    dual_lsb[i*2+1] = samples_bytes[i*2+1] & 1    # LSB of high byte
dual_padded = np.pad(dual_lsb, (0, 8 - len(dual_lsb) % 8) if len(dual_lsb) % 8 else (0, 0))
dual_bytes = np.packbits(dual_padded).tobytes()[:len(dual_lsb)//8]
dual_block = dual_bytes[:882]  # 2x size
print(f"Dual LSB block: {len(dual_block)} bytes")  
for sig, name in [(b'PK\x03\x04', 'ZIP'), (b'iCS{', 'FLAG'), (b'ICS{', 'FLAG')]:
    if sig in dual_bytes[:5000]:
        idx = dual_bytes.index(sig)
        print(f"  FOUND {name} at {idx}!")
        if name == 'FLAG':
            end = dual_bytes.find(b'}', idx)
            if end != -1:
                print(f"    {dual_bytes[idx:end+1].decode()}")

# ===== Try extracting bits from specific sample offsets =====
print("\n=== 200-offset LSB ===")
# Start at sample 200, take every 200th sample
subset_bits = (samples[200::200] & 1).astype(np.uint8)
sub_padded = np.pad(subset_bits, (0, 8 - len(subset_bits) % 8) if len(subset_bits) % 8 else (0, 0))
sub_bytes = np.packbits(sub_padded).tobytes()[:len(subset_bits)//8]
print(f"stride=200, start=200: {len(sub_bytes)} bytes")
for sig, name in [(b'PK\x03\x04', 'ZIP')]:
    if sig in sub_bytes:
        print(f"  FOUND {name}!")

# ===== Look at actual 21x21 image details =====
print("\n=== 21x21 Image Analysis ===")
# Check pixel distribution
pixel_vals = pixels.flatten()
print(f"Mean: {pixel_vals.mean():.1f}, Std: {pixel_vals.std():.1f}")
print(f"Min: {pixel_vals.min()}, Max: {pixel_vals.max()}")
print(f"Pixels > 128: {sum(pixel_vals > 128)}, <= 128: {sum(pixel_vals <= 128)}")

# Check if pixel values have a narrow distribution (like 0 and 255 only)
unique_vals = sorted(set(pixel_vals))
print(f"Unique pixel values: {unique_vals[:20]}")
if len(unique_vals) < 10:
    print(f"Only {len(unique_vals)} unique values - might be quantized/encoded!")

# ===== Generate 21x21 image at various scales =====
for scale in [10, 20, 40]:
    img = Image.fromarray(pixels, mode='L')
    img = img.resize((21*scale, 21*scale), Image.NEAREST)
    img.save(f'D:/test/CTF/7981/block_21x21_x{scale}.png')
    # Also save inverted
    img_inv = Image.fromarray(255 - pixels, mode='L')
    img_inv = img_inv.resize((21*scale, 21*scale), Image.NEAREST)
    img_inv.save(f'D:/test/CTF/7981/block_21x21_inv_x{scale}.png')

print("21x21 images saved at various scales")
