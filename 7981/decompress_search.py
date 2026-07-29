import struct, numpy as np, zlib, lzma, bz2, gzip

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

# ===== Try decompressing the block with various algorithms =====
print("=== Decompression attempts ===")
for name, func in [('zlib', lambda d: zlib.decompress(d)),
                    ('zlib -15', lambda d: zlib.decompress(d, -15)),
                    ('gzip', lambda d: gzip.decompress(d)),
                    ('bz2', lambda d: bz2.decompress(d)),
                    ('lzma', lambda d: lzma.decompress(d))]:
    try:
        result = func(block)
        print(f"{name}: SUCCESS - {len(result)} bytes")
        text = ''.join(chr(b) if 32<=b<=126 else '.' for b in result[:100])
        print(f"  First 100: {text}")
        for pat in [b'iCS{', b'ICS{', b'flag{', b'FLAG{', b'CTF{']:
            if pat in result:
                idx = result.index(pat)
                end = result.find(b'}', idx)
                if end != -1:
                    print(f"  FLAG: {result[idx:end+1].decode()}")
    except Exception as e:
        print(f"{name}: {type(e).__name__}")

# Try the full LSB data as a compressed file
print("\n=== Full LSB decompression ===")
for name, func in [('zlib', lambda d: zlib.decompress(d)),
                    ('gzip', lambda d: gzip.decompress(d))]:
    try:
        result = func(lsb_bytes)
        print(f"{name}: SUCCESS - {len(result)} bytes")
        if len(result) < 500:
            print(f"  Content: {result}")
        else:
            print(f"  First 100: {result[:100].hex()}")
            for pat in [b'iCS{', b'ICS{', b'flag{', b'FLAG{', b'CTF{']:
                if pat in result:
                    idx = result.index(pat)
                    end = result.find(b'}', idx)
                    if end != -1:
                        print(f"  FLAG: {result[idx:end+1].decode()}")
    except Exception as e:
        print(f"{name}: {type(e).__name__}")

# ===== Try passwords =====
print("\n=== Password candidates ===")
passwords = [
    "7981", "200", "00",
    "18.344167N 66.752778W", "Arecibo", "arecibo",
    "IGSS", "igss",
    "STAGONAGRAPHY", "stagonagraphy",
    "441", "44100",
]
for pw in passwords:
    print(f"  '{pw}'")

# ===== Look at the spectrogram image for hidden text =====
# Maybe the spectrogram shows the password as text
print("\n=== Checking audio for embedded ZIP at specific offsets ===")
# Look for PK signature in the raw audio bytes (not LSB)
for i in range(0, len(raw) - 4):
    if raw[i:i+4] == b'PK\x03\x04':
        print(f"FOUND ZIP in raw audio at offset {i}!")
        # Check size
        size_field = struct.unpack_from('<I', raw, i+18)[0]
        csize_field = struct.unpack_from('<I', raw, i+18)[0]
        print(f"  Compressed size: {csize_field}")
        
print("=== Checking raw audio for other file signatures ===")
for sig, name in [(b'\x89PNG', 'PNG'), (b'\xff\xd8\xff', 'JPEG'),
                   (b'GIF8', 'GIF'), (b'%PDF', 'PDF')]:
    for i in range(0, len(raw) - len(sig)):
        if raw[i:i+len(sig)] == sig and i > 100:  # skip the RIFF header area
            print(f"FOUND {name} in raw file at offset {i}")
