import struct

with open('D:/test/CTF/The Final Rehearsal/rehearsal_laptop.E01', 'rb') as f:
    image_data = f.read()

bps = 512; spc = 8; reserved_sectors = 32; num_fats = 2; sectors_per_fat = 32
data_area_start = reserved_sectors + (num_fats * sectors_per_fat)
fat_offset = reserved_sectors * bps

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

# Debug fmt chunk parsing
fmt_offset = 22
print(f"Raw fmt bytes (offset {fmt_offset}):")
print(f"  Bytes 0-3 (ID): {orphan_data[fmt_offset:fmt_offset+4]} = '{orphan_data[fmt_offset:fmt_offset+4].decode()}'")
print(f"  Bytes 4-7 (size): {orphan_data[fmt_offset+4:fmt_offset+8].hex()} = {struct.unpack_from('<I', orphan_data, fmt_offset+4)[0]}")

fmt_data = orphan_data[fmt_offset+8:fmt_offset+24]
print(f"  Bytes 8-23 (fmt data): {fmt_data.hex()}")

audio_fmt = struct.unpack_from('<H', orphan_data, fmt_offset+8)[0]
channels = struct.unpack_from('<H', orphan_data, fmt_offset+10)[0]
sample_rate = struct.unpack_from('<I', orphan_data, fmt_offset+12)[0]
byte_rate = struct.unpack_from('<I', orphan_data, fmt_offset+16)[0]
block_align = struct.unpack_from('<H', orphan_data, fmt_offset+20)[0]
bits = struct.unpack_from('<H', orphan_data, fmt_offset+22)[0]

print(f"  audio_fmt={audio_fmt}, ch={channels}, rate={sample_rate}, byte_rate={byte_rate}, align={block_align}, bits={bits}")

# Data chunk
data_offset = 46
print(f"\nRaw data chunk (offset {data_offset}):")
print(f"  ID: {orphan_data[data_offset:data_offset+4]}")
data_size = struct.unpack_from('<I', orphan_data, data_offset+4)[0]
print(f"  Size: {data_size}")

audio_start = data_offset + 8
audio_data = orphan_data[audio_start:audio_start + data_size]
duration = data_size / (sample_rate * channels * bits / 8)
print(f"\nAudio: {duration:.2f}s, {data_size} bytes, {len(audio_data) // (bits//8)} samples")

# LSB extraction
lsb_bytes = bytearray()
for i in range(0, min(len(audio_data) - 1, data_size), 2):
    sample = struct.unpack_from('<h', audio_data, i)[0]
    lsb_bytes.append(sample & 1)

# Convert bits to bytes
bit_str = ''.join(str(b) for b in lsb_bytes)
result_bytes = bytearray()
for i in range(0, len(bit_str) - 7, 8):
    result_bytes.append(int(bit_str[i:i+8], 2))

print(f"\nLSB data: {len(result_bytes)} bytes")
# Search for flag
for pattern in [b'iCS{', b'ICS{', b'flag{', b'FLAG{']:
    idx = result_bytes.find(pattern)
    if idx >= 0:
        end = result_bytes.find(b'}', idx)
        if end >= 0:
            flag = result_bytes[idx:end+1].decode('ascii', errors='replace')
            print(f"  FLAG IN LSB: {flag}")
        else:
            print(f"  Found {pattern} at {idx} (no closing brace)")

# Also try LSB of second byte (higher precision LSB)
lsb2 = bytearray()
for i in range(0, min(len(audio_data) - 1, data_size), 2):
    sample = struct.unpack_from('<h', audio_data, i)[0]
    lsb2.append((sample >> 1) & 1)
bit_str2 = ''.join(str(b) for b in lsb2)
result2 = bytearray()
for i in range(0, len(bit_str2) - 7, 8):
    result2.append(int(bit_str2[i:i+8], 2))
for pattern in [b'iCS{', b'ICS{']:
    idx = result2.find(pattern)
    if idx >= 0:
        end = result2.find(b'}', idx)
        if end >= 0:
            print(f"  FLAG IN LSB bit1: {result2[idx:end+1].decode('ascii', errors='replace')}")

# Try extracting MSB from samples (top bit)
msb_bytes = bytearray()
for i in range(0, min(len(audio_data) - 1, data_size), 2):
    sample = struct.unpack_from('<h', audio_data, i)[0]
    msb_bytes.append((sample >> 15) & 1)
bit_str_msb = ''.join(str(b) for b in msb_bytes)
result_msb = bytearray()
for i in range(0, len(bit_str_msb) - 7, 8):
    result_msb.append(int(bit_str_msb[i:i+8], 2))
for pattern in [b'iCS{', b'ICS{']:
    idx = result_msb.find(pattern)
    if idx >= 0:
        end = result_msb.find(b'}', idx)
        if end >= 0:
            print(f"  FLAG IN MSB: {result_msb[idx:end+1].decode('ascii', errors='replace')}")

# Check the metadata area thoroughly
metadata_start = audio_start + data_size
metadata = orphan_data[metadata_start:]
print(f"\nMetadata: {len(metadata)} bytes from offset {metadata_start}")

# Find LIST INFO
for idx in range(len(metadata)):
    if metadata[idx:idx+4] == b'LIST':
        list_size = struct.unpack_from('<I', metadata, idx+4)[0]
        print(f"\nLIST at metadata[{idx}], size={list_size}")
        list_data = metadata[idx+8:idx+8+list_size]
        print(f"  Type: {metadata[idx+8:idx+12]}")
        # Parse INFO sub-chunks
        pos = 4
        while pos < len(list_data):
            sub_id = list_data[pos:pos+4]
            sub_size = struct.unpack_from('<I', list_data, pos+4)[0]
            sub_data = list_data[pos+8:pos+8+sub_size]
            try:
                id_str = sub_id.decode('ascii')
                data_str = sub_data.decode('ascii', errors='replace').rstrip('\x00')
                print(f"  {id_str}: {repr(data_str)}")
            except:
                pass
            pos += 8 + sub_size
        break
