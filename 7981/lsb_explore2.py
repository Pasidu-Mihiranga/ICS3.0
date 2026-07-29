import struct
import numpy as np
import re

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
lsb_bytes = bytes(int(lsb_bits[i:i+8], 2) for i in range(0, len(lsb_bits) - 7, 8))

print(f"LSB data: {len(lsb_bytes)} bytes")

# === Look for the archive signature ===
# Check every possible offset for ZIP/GZ/RAR/7z
for sig, name, ext in [(b'PK\x03\x04', 'ZIP', '.zip'), (b'\x1f\x8b\x08', 'GZIP', '.gz'),
                          (b'Rar!\x1a\x07', 'RAR', '.rar'), (b'7z\xbc\xaf\x27\x1c', '7Z', '.7z'),
                          (b'BZh', 'BZ2', '.bz2')]:
    idx = 0
    while True:
        idx = lsb_bytes.find(sig, idx)
        if idx == -1:
            break
        print(f"FOUND {name} signature at offset {idx}")
        # Check if this is a valid file
        if name == 'ZIP':
            # Look for central directory
            eocd = lsb_bytes.rfind(b'PK\x05\x06')
            if eocd != -1:
                total_size = eocd + 22  # EOCD is 22 bytes min
                with open(f'D:/test/CTF/7981/lsb_archive{ext}', 'wb') as f:
                    f.write(lsb_bytes[idx:total_size])
                print(f"  Extracted {total_size-idx} bytes to lsb_archive{ext}")
        elif name == 'GZIP':
            with open(f'D:/test/CTF/7981/lsb_archive{ext}', 'wb') as f:
                f.write(lsb_bytes[idx:])
            print(f"  Extracted to lsb_archive{ext}")
        idx += 1

# === Look for readable strings of varying lengths ===
text = lsb_bytes.decode('ascii', errors='replace')
print("\n=== Longest printable strings ===")
# Find all printable strings
strings = []
current = ''
for c in text:
    if c.isprintable():
        current += c
    else:
        if len(current) >= 6:
            strings.append(current)
        current = ''
if len(current) >= 6:
    strings.append(current)

strings.sort(key=len, reverse=True)
for s in strings[:30]:
    idx = text.find(s)
    print(f"  len={len(s):3d} offset={idx:7d}: '{s}'")

# === Look for base64 patterns ===
b64_pattern = re.findall(r'[A-Za-z0-9+/=]{16,}', text)
print(f"\nBase64-like strings ({len(b64_pattern)} found):")
for s in b64_pattern[:10]:
    idx = text.find(s)
    print(f"  offset={idx}: '{s[:80]}'")

# === Check if LSB data forms a hex string ===
hex_chars = sum(1 for c in text if c in '0123456789abcdefABCDEF')
print(f"\nHex character ratio: {hex_chars/len(text)*100:.1f}%")

# === Look for repeated patterns ===
for pattern_len in [4, 8, 16, 32]:
    patterns = {}
    for i in range(0, len(lsb_bytes) - pattern_len, pattern_len):
        pat = lsb_bytes[i:i+pattern_len]
        patterns[pat] = patterns.get(pat, 0) + 1
    repeats = [(k, v) for k, v in patterns.items() if v > 3]
    if repeats:
        repeats.sort(key=lambda x: -x[1])
        print(f"\nRepeated {pattern_len}-byte patterns (>{3} times):")
        for pat, count in repeats[:5]:
            print(f"  {pat.hex()} appears {count} times")
