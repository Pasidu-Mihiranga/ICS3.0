import struct

with open('D:/test/CTF/The Final Rehearsal/rehearsal_laptop.E01', 'rb') as f:
    image_data = f.read()

bps = 512; spc = 8; reserved_sectors = 32; num_fats = 2; sectors_per_fat = 32
data_area_start = reserved_sectors + (num_fats * sectors_per_fat)
fat_offset = reserved_sectors * bps

# Extract orphan data
cluster = 3
orphan_data = b''
visited = set()
while cluster != 0x0FFFFFFF and cluster != 0 and cluster not in visited:
    visited.add(cluster)
    sector = data_area_start + (cluster - 2) * spc
    offset = sector * bps
    orphan_data += image_data[offset:offset + spc * bps]
    next_cluster = struct.unpack_from('<I', image_data, fat_offset + cluster * 4)[0] & 0x0FFFFFFF
    cluster = next_cluster

# Audio params from fmt chunk (at offset 22 in orphan_data)
# fmt chunk: bytes 22-45
fmt_size = struct.unpack_from('<I', orphan_data, 26)[0]
audio_fmt = struct.unpack_from('<H', orphan_data, 30)[0]
channels = struct.unpack_from('<H', orphan_data, 32)[0]
sample_rate = struct.unpack_from('<I', orphan_data, 34)[0]
byte_rate = struct.unpack_from('<I', orphan_data, 38)[0]
block_align = struct.unpack_from('<H', orphan_data, 42)[0]
bits_per_sample = struct.unpack_from('<H', orphan_data, 44)[0]

# data chunk at offset 46
data_id = orphan_data[46:50]
data_size = struct.unpack_from('<I', orphan_data, 50)[0]
audio_start = 54
audio_data = orphan_data[audio_start:audio_start + data_size]

print(f"Audio: {sample_rate}Hz, {bits_per_sample}-bit, {channels}ch, {data_size} samples")
print(f"Duration: {data_size / (sample_rate * channels * bits_per_sample/8):.2f}s")
print(f"Audio data range: {audio_start} to {audio_start + data_size}")
print(f"Beyond audio: {len(orphan_data) - (audio_start + data_size)} bytes")

# ====== LSB STEGANOGRAPHY ANALYSIS ======
# Extract LSB from each 16-bit sample
num_samples = data_size // 2
lsb_bits = ''
for i in range(0, min(num_samples * 2, data_size), 2):
    sample = struct.unpack_from('<h', audio_data, i)[0]
    lsb_bits += str(sample & 1)

# Convert to bytes
lsb_bytes = bytearray()
for i in range(0, len(lsb_bits) - 7, 8):
    byte_val = int(lsb_bits[i:i+8], 2)
    lsb_bytes.append(byte_val)

print(f"\nLSB extraction: {len(lsb_bytes)} bytes from {num_samples} samples")
print(f"First 100 LSB bytes:")
print(f"  Hex: {lsb_bytes[:100].hex()}")
print(f"  ASCII: {repr(lsb_bytes[:100])}")

# Check if LSB data contains readable text or a flag
try:
    text = lsb_bytes.decode('ascii', errors='replace')
    flag_indices = []
    for pattern in ['iCS{', 'ICS{', 'flag{', 'FLAG{', 'CTF{']:
        idx = text.find(pattern)
        if idx >= 0:
            flag_indices.append((idx, pattern))
    if flag_indices:
        print(f"\n  FLAGS FOUND IN LSB:")
        for idx, pat in flag_indices:
            end = text.find('}', idx)
            if end >= 0:
                print(f"    {text[idx:end+1]}")
    # Show printable substrings
    for line in text.split('\n'):
        stripped = ''.join(c for c in line if c.isprintable() or c in '{}')
        if len(stripped) > 5:
            print(f"  LSB text: {stripped[:100]}")
except:
    pass

# ====== Look for ASCII text directly in PCM samples ======
print(f"\n\nASCII search in raw PCM (sample values as chars):")
pcm_chars = bytearray()
for i in range(0, min(num_samples * 2, data_size), 2):
    val = struct.unpack_from('<h', audio_data, i)[0]
    byte_val = abs(val) & 0xFF
    if 32 <= byte_val <= 126:
        pcm_chars.append(byte_val)
    elif byte_val == 0:
        pcm_chars.append(0)

pcm_text = pcm_chars.decode('ascii', errors='replace')
for pattern in ['iCS{', 'ICS{', 'flag{']:
    idx = pcm_text.find(pattern)
    if idx >= 0:
        end = pcm_text.find('}', idx)
        if end >= 0:
            print(f"  FOUND: {pcm_text[idx:end+1]}")

# ====== Check metadata after audio for hidden data ======
metadata = orphan_data[audio_start + data_size:]
print(f"\n\nMetadata region ({len(metadata)} bytes):")
# Find LIST chunk
list_idx = metadata.find(b'LIST')
if list_idx >= 0:
    print(f"  LIST at metadata offset {list_idx}:")
    print(f"  {repr(metadata[list_idx:list_idx+100])}")

# Check for any data after the LIST chunk
info_size = struct.unpack_from('<I', metadata, list_idx + 4)[0]
list_end = list_idx + 8 + info_size
after_list = metadata[list_end:]
print(f"\n  After LIST chunk ({len(after_list)} bytes):")
non_zero = after_list.rstrip(b'\x00')
if len(non_zero) > 0:
    print(f"  Non-zero: {repr(non_zero[:200])}")
else:
    print(f"  All zeros")

# ====== Search for the hex string or flag in ALL orphan data ======
print(f"\n\nFULL ORPHAN DATA SEARCH:")
for pattern in [b'iCS{', b'ICS{']:
    idx = orphan_data.find(pattern)
    if idx >= 0:
        end_idx = orphan_data.find(b'}', idx)
        if end_idx >= 0:
            flag = orphan_data[idx:end_idx+1].decode('ascii', errors='replace')
            print(f"  FOUND FLAG at offset {idx}: {flag}")
        else:
            print(f"  Found '{pattern.decode()}' at {idx} but no closing brace")
    else:
        print(f"  Pattern '{pattern.decode()}' not found")

# Also check the reconstructed WAV 
riff_header = b'RIFF' + struct.pack('<I', len(orphan_data) - 8) + b'WAVE'
reconstructed = riff_header + orphan_data[12:]
for pattern in [b'iCS{', b'ICS{']:
    idx = reconstructed.find(pattern)
    if idx >= 0:
        end_idx = reconstructed.find(b'}', idx)
        if end_idx >= 0:
            print(f"  In reconstructed: {reconstructed[idx:end_idx+1].decode('ascii', errors='replace')}")
