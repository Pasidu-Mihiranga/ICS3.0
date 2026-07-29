import struct

with open('D:/test/CTF/The Final Rehearsal/rehearsal_laptop.E01', 'rb') as f:
    image_data = f.read()

bps = 512; spc = 8; reserved_sectors = 32; num_fats = 2; sectors_per_fat = 32
data_area_start = reserved_sectors + (num_fats * sectors_per_fat)
fat_offset = reserved_sectors * bps

# Follow FAT chain from cluster 3
cluster = 3
orphan = b''
visited = set()
while cluster != 0x0FFFFFFF and cluster != 0 and cluster not in visited:
    visited.add(cluster)
    sector = data_area_start + (cluster - 2) * spc
    off = sector * bps
    orphan += image_data[off:off + spc * bps]
    next_cluster = struct.unpack_from('<I', image_data, fat_offset + cluster * 4)[0] & 0x0FFFFFFF
    cluster = next_cluster

# CORRECTED offsets: RIFF header is 12 bytes (offset 0-11) zeroed
# fmt chunk starts at offset 12
fmt_chunk_size = struct.unpack_from('<I', orphan, 16)[0]  # should be 16
audio_format = struct.unpack_from('<H', orphan, 20)[0]
channels = struct.unpack_from('<H', orphan, 22)[0]
sample_rate = struct.unpack_from('<I', orphan, 24)[0]
byte_rate = struct.unpack_from('<I', orphan, 28)[0]
block_align = struct.unpack_from('<H', orphan, 32)[0]
bits = struct.unpack_from('<H', orphan, 34)[0]

# data chunk at offset 36
data_size = struct.unpack_from('<I', orphan, 40)[0]
audio_start = 44
audio_data = orphan[audio_start:audio_start + data_size]

duration = data_size / (sample_rate * channels * bits / 8)
print(f"Audio: {sample_rate}Hz, {bits}-bit, {channels}ch, {duration:.2f}s")
print(f"Data size: {data_size}, samples: {len(audio_data)//2}")

# ============ LSB STEGANOGRAPHY ============
print(f"\n=== LSB ANALYSIS ===")
lsb = ''.join(str(struct.unpack_from('<h', audio_data, i)[0] & 1) 
              for i in range(0, len(audio_data)-1, 2))

lsb_result = bytes(int(lsb[i:i+8], 2) for i in range(0, len(lsb)-7, 8))

for pattern in [b'iCS{', b'ICS{', b'flag{']:
    idx = lsb_result.find(pattern)
    if idx >= 0:
        end = lsb_result.find(b'}', idx) if idx >= 0 else -1
        if end >= 0:
            print(f"LSB FLAG: {lsb_result[idx:end+1].decode()}")
        else:
            print(f"Found {pattern} in LSB at {idx}")

# Try different bits
for bit_pos in [1, 2, 3, 7, 8, 15]:
    bits_str = ''.join(str((struct.unpack_from('<h', audio_data, i)[0] >> bit_pos) & 1)
                       for i in range(0, min(len(audio_data)-1, 50000), 2))
    result = bytes(int(bits_str[i:i+8], 2) for i in range(0, len(bits_str)-7, 8))
    for pat in [b'iCS{', b'ICS{']:
        idx = result.find(pat)
        if idx >= 0:
            end = result.find(b'}', idx)
            if end >= 0:
                print(f"Bit{bit_pos} FLAG: {result[idx:end+1].decode()}")

# ============ AMPLITUDE MODULATION CHECK ============
# Check if sample amplitudes encode characters
print(f"\n=== AMPLITUDE ANALYSIS ===")
# Look at high byte of each sample
hi_bytes = bytearray()
for i in range(0, min(len(audio_data)-1, data_size), 2):
    sample = struct.unpack_from('<h', audio_data, i)[0]
    lo = sample & 0xFF
    hi = (sample >> 8) & 0x7F
    hi_bytes.append(hi)

hi_str = bytes(hi_bytes)
for pat in [b'iCS{', b'ICS{']:
    idx = hi_str.find(pat)
    if idx >= 0:
        end = hi_str.find(b'}', idx)
        if end >= 0:
            print(f"High-byte FLAG: {hi_str[idx:end+1].decode()}")

# ============ METADATA EXAMINATION ============
print(f"\n=== METADATA ===")
meta = orphan[audio_start + data_size:]
list_idx = meta.find(b'LIST')
if list_idx >= 0:
    lsize = struct.unpack_from('<I', meta, list_idx + 4)[0]
    linfo = meta[list_idx+8:list_idx+8+lsize]
    pos = 4
    while pos < len(linfo) - 8:
        sid = linfo[pos:pos+4]
        ssize = struct.unpack_from('<I', linfo, pos+4)[0]
        sdata = linfo[pos+8:pos+8+ssize]
        try:
            print(f"  {sid.decode().strip()}: {repr(sdata.rstrip(b'\\x00').decode('ascii', errors='replace'))}")
        except:
            print(f"  {sid}: {sdata.hex()}")
        pos += 8 + ssize
    
    # After LIST, check for any more data
    after = meta[list_idx + 8 + lsize:]
    nonzero = after.rstrip(b'\x00')
    if len(nonzero) > 0:
        print(f"\nAfter LIST ({len(nonzero)} non-zero bytes):")
        print(f"  {repr(nonzero[:200])}")

# Save reconstructed WAV
riff_header = b'RIFF' + struct.pack('<I', len(orphan) - 8) + b'WAVE'
reconstructed = riff_header + orphan[12:]
with open('C:/Users/Milindu/AppData/Local/Temp/kilo/VOICE_NOTE_FINAL.wav', 'wb') as f:
    f.write(reconstructed)
print(f"\nReconstructed WAV saved ({len(reconstructed)} bytes)")

# Search entire orphan for flag
for pat in [b'iCS{', b'ICS{']:
    idx = orphan.find(pat)
    if idx >= 0:
        end = orphan.find(b'}', idx)
        if end >= 0:
            print(f"FLAG IN ORPHAN: {orphan[idx:end+1].decode()}")
