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

# Try XOR full LSB with various keys to reveal ZIP
keys_to_try = [
    b'\x79\x81',           # 7981 as bytes
    b'\xc8',               # 200
    bytes([79, 81]),       # 79, 81
    b'STAGONAGRAPHY',      # hint
    b'7981',               # as ASCII
    b'441',                # block size
    b'\x1b\xfe',           # first 2 bytes of block
    b'44100',              # sample rate
    b'Arecibo',            # observatory name
    b'arecibo',
    b'18.344167N',
    b'66.752778W',
]

for key in keys_to_try:
    xored = bytes(lsb_bytes[i] ^ key[i % len(key)] for i in range(len(lsb_bytes)))
    # Check first 2000 bytes for ZIP
    if b'PK\x03\x04' in xored[:2000]:
        idx = xored.index(b'PK\x03\x04')
        print(f"XOR '{key}': FOUND ZIP at {idx}!")
        # Find EOCD
        eocd = xored.rfind(b'PK\x05\x06')
        if eocd != -1:
            with open(f'D:/test/CTF/7981/zip_{key[:6].hex()}.zip', 'wb') as f:
                f.write(xored[idx:eocd+22])
            print(f"  Saved ZIP ({eocd+22-idx} bytes)")

# Also try searching raw WAV for ZIP embedded directly
print("\n=== Searching raw WAV for ZIP ===")
for i in range(len(raw) - 4):
    if raw[i:i+4] == b'PK\x03\x04':
        # Check if valid ZIP
        print(f"ZIP LOCAL HEADER at offset {i}")
        nlen = struct.unpack_from('<H', raw, i+26)[0]
        elen = struct.unpack_from('<H', raw, i+28)[0]
        name = raw[i+30:i+30+nlen]
        print(f"  File: {name}")
        # Find EOCD
        eocd = raw.rfind(b'PK\x05\x06')
        if eocd != -1:
            with open(f'D:/test/CTF/7981/embedded.zip', 'wb') as f:
                f.write(raw[i:eocd+22])
            print(f"  Extracted ZIP ({eocd+22-i} bytes)")

# Search raw WAV for other file sigs
print("\n=== Other file signatures in raw WAV ===")
for sig, name in [(b'\x89PNG\r\n\x1a\n', 'PNG'), (b'GIF89a', 'GIF89'),
                   (b'Rar!\x1a\x07', 'RAR'), (b'7z\xbc\xaf\x27\x1c', '7Z'),
                   (b'\x1f\x8b\x08', 'GZIP'), (b'\xfd7zXZ\x00', 'XZ')]:
    idx = raw.find(sig, 100)  # skip header
    if idx != -1:
        print(f"FOUND {name} at offset {idx}")
        with open(f'D:/test/CTF/7981/embedded_{name.lower()}.bin', 'wb') as f:
            f.write(raw[idx:idx+1000000])  # grab up to 1MB
        print(f"  Extracted to embedded_{name.lower()}.bin")

# Check raw audio bytes (2 bytes per sample = 16-bit) for embedded data
print("\n=== Raw audio samples as bytes ===")
raw_audio_bytes = audio  # raw PCM data
for sig, name in [(b'PK\x03\x04', 'ZIP'), (b'\x1f\x8b\x08', 'GZIP')]:
    idx = raw_audio_bytes.find(sig)
    print(f"{name} in raw PCM: {'FOUND at '+str(idx) if idx != -1 else 'NOT FOUND'}")

# Check if reversing the sample byte order reveals anything
swapped = bytearray()
for i in range(0, len(audio), 2):
    if i + 1 < len(audio):
        swapped.append(audio[i+1])
        swapped.append(audio[i])
swapped_bytes = bytes(swapped)
for sig, name in [(b'PK\x03\x04', 'ZIP')]:
    idx = swapped_bytes.find(sig)
    print(f"Byte-swapped PCM {name}: {'FOUND at '+str(idx) if idx != -1 else 'NOT FOUND'}")

# Also try the raw file (NOT audio data) after RIFF header
print("\n=== WAV file structure analysis ===")
print(f"Total file size: {len(raw)} bytes")
print(f"RIFF size field: {struct.unpack_from('<I', raw, 4)[0]}")
print(f"Expected total: {struct.unpack_from('<I', raw, 4)[0] + 8}")
# Check for data beyond expected end
expected = struct.unpack_from('<I', raw, 4)[0] + 8
extra = len(raw) - expected
if extra > 0:
    print(f"EXTRA DATA beyond RIFF: {extra} bytes at offset {expected}")
    extra_data = raw[expected:]
    print(f"  First 100: {extra_data[:100].hex()}")
    if b'PK' in extra_data or b'flag' in extra_data:
        print(f"  ZIP/flag found in extra data!")
