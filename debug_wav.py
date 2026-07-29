import struct

with open('D:/test/CTF/The Final Rehearsal/rehearsal_laptop.E01', 'rb') as f:
    image_data = f.read()

bps = 512; spc = 8; reserved_sectors = 32; num_fats = 2; sectors_per_fat = 32
data_area_start = reserved_sectors + (num_fats * sectors_per_fat)
fat_offset = reserved_sectors * bps

# Read cluster 3 directly
sector = data_area_start + (3 - 2) * spc
offset = sector * bps
raw_data = image_data[offset:offset + 100]
print(f"Cluster 3 starts at sector {sector}, offset {offset}")
print(f"First 100 bytes raw: {raw_data.hex()}")
print(f"ASCII: {repr(raw_data[:100])}")

# Check if it matches expected
print(f"\nExpected 'fmt ' at offset 22: {raw_data[22:26]}")
print(f"Should be: 66 6d 74 20")

# Follow the full chain
cluster = 3
orphan_data = b''
visited = set()
while cluster != 0x0FFFFFFF and cluster != 0 and cluster not in visited:
    visited.add(cluster)
    sector = data_area_start + (cluster - 2) * spc
    off = sector * bps
    chunk = image_data[off:off + spc * bps]
    orphan_data += chunk
    fat_entry_offset = fat_offset + cluster * 4
    next_val = struct.unpack_from('<I', image_data, fat_entry_offset)[0]
    next_cluster = next_val & 0x0FFFFFFF
    cluster = next_cluster

print(f"\nOrphan data total: {len(orphan_data)} bytes")
print(f"First 80 bytes: {orphan_data[:80].hex()}")

# Now read the fmt chunk from orphan_data directly
fmt_offset = 22
print(f"\normat_data[{fmt_offset}:{fmt_offset+4}] = {orphan_data[fmt_offset:fmt_offset+4]}")
print(f"Should be 'fmt ': {orphan_data[fmt_offset:fmt_offset+4] == b'fmt '}")

# Parse correctly
fmt_id = orphan_data[22:26]
fmt_chunk_size = struct.unpack_from('<I', orphan_data, 26)[0]
audio_format = struct.unpack_from('<H', orphan_data, 30)[0]
num_channels = struct.unpack_from('<H', orphan_data, 32)[0]
sample_rate = struct.unpack_from('<I', orphan_data, 34)[0]
byte_rate = struct.unpack_from('<I', orphan_data, 38)[0]
block_align = struct.unpack_from('<H', orphan_data, 42)[0]
bits_per_sample = struct.unpack_from('<H', orphan_data, 44)[0]

print(f"fmt_id: {fmt_id}")
print(f"fmt_chunk_size: {fmt_chunk_size}")
print(f"audio_format: {audio_format}")
print(f"channels: {num_channels}")
print(f"sample_rate: {sample_rate}")
print(f"byte_rate: {byte_rate}")
print(f"block_align: {block_align}")
print(f"bits_per_sample: {bits_per_sample}")

# Parse data chunk
data_id = orphan_data[46:50]
data_chunk_size = struct.unpack_from('<I', orphan_data, 50)[0]
print(f"\ndata_id: {data_id}")
print(f"data_chunk_size: {data_chunk_size}")

audio_start = 54
audio_data = orphan_data[audio_start:audio_start + data_chunk_size]
duration = data_chunk_size / (sample_rate * num_channels * bits_per_sample / 8)
print(f"Duration: {duration:.2f}s")

# Now LSB extraction
lsb_bits = []
for i in range(0, len(audio_data) - 1, 2):
    sample = struct.unpack_from('<h', audio_data, i)[0]
    lsb_bits.append(str(sample & 1))

bit_string = ''.join(lsb_bits)
lsb_result = bytearray()
for i in range(0, len(bit_string) - 7, 8):
    lsb_result.append(int(bit_string[i:i+8], 2))

print(f"\nLSB results: {len(lsb_result)} bytes")
for pattern in [b'iCS{', b'ICS{', b'flag{']:
    idx = lsb_result.find(pattern)
    if idx >= 0:
        end = lsb_result.find(b'}', idx)
        if end >= 0:
            print(f"FOUND FLAG IN LSB: {lsb_result[idx:end+1].decode()}")

# Also check metadata
meta = orphan_data[audio_start + data_chunk_size:]
print(f"\nMetadata size: {len(meta)} bytes")
list_idx = meta.find(b'LIST')
if list_idx >= 0:
    lsize = struct.unpack_from('<I', meta, list_idx + 4)[0]
    print(f"LIST at meta[{list_idx}], size={lsize}")
    linfo = meta[list_idx+8:list_idx+8+lsize]
    print(f"Type: {linfo[:4]}")
    pos = 4
    while pos < len(linfo):
        sid = linfo[pos:pos+4]
        ssize = struct.unpack_from('<I', linfo, pos+4)[0]
        sdata = linfo[pos+8:pos+8+ssize]
        try:
            print(f"  {sid.decode()}: {sdata.decode('ascii', errors='replace').rstrip(chr(0))}")
        except:
            print(f"  {sid}: {sdata.hex()}")
        pos += 8 + ssize
