import struct

with open('D:/test/CTF/The Final Rehearsal/rehearsal_laptop.E01', 'rb') as f:
    image_data = f.read()

bps = 512; spc = 8; reserved_sectors = 32; num_fats = 2; sectors_per_fat = 32
data_area_start = reserved_sectors + (num_fats * sectors_per_fat)
fat_offset = reserved_sectors * bps

# Follow FAT chain from cluster 3
cluster = 3
orphan_data = b''
visited = set()
while cluster != 0x0FFFFFFF and cluster != 0 and cluster not in visited:
    visited.add(cluster)
    sector = data_area_start + (cluster - 2) * spc
    offset = sector * bps
    orphan_data += image_data[offset:offset + spc * bps]
    fat_entry_offset = fat_offset + cluster * 4
    next_cluster = struct.unpack_from('<I', image_data, fat_entry_offset)[0] & 0x0FFFFFFF
    cluster = next_cluster

print(f"Orphan data: {len(orphan_data)} bytes")

# Reconstruct RIFF header
# First 12 bytes (0-11) were the original RIFF header, now zeroed
# RIFF size = total_size - 8
riff_size = len(orphan_data) - 8
riff_header = b'RIFF' + struct.pack('<I', riff_size) + b'WAVE'
print(f"Reconstructed RIFF header: {riff_header.hex()}")

# Full reconstructed WAV
reconstructed = riff_header + orphan_data[12:]
print(f"Reconstructed WAV size: {len(reconstructed)} bytes")

# Save the WAV
output_path = 'C:/Users/Milindu/AppData/Local/Temp/kilo/VOICE_NOTE_FINAL.wav'
with open(output_path, 'wb') as f:
    f.write(reconstructed)
print(f"Saved to {output_path}")

# Analyze the WAV structure
print(f"\nWAV analysis:")
print(f"  RIFF: {reconstructed[0:4]}")
print(f"  Size: {struct.unpack('<I', reconstructed[4:8])[0]}")
print(f"  Format: {reconstructed[8:12]}")
print(f"  Bytes 12-21: {reconstructed[12:22].hex()}")

# Parse chunks
offset = 22  # fmt chunk starts at 22
while offset < len(reconstructed) - 8:
    chunk_id = reconstructed[offset:offset+4]
    chunk_size = struct.unpack('<I', reconstructed[offset+4:offset+8])[0]
    print(f"  Chunk at {offset}: '{chunk_id.decode('ascii', errors='replace')}' size={chunk_size}")
    
    if chunk_id == b'fmt ':
        fmt = reconstructed[offset+8:offset+8+chunk_size]
        audio_fmt = struct.unpack('<H', fmt[0:2])[0]
        channels = struct.unpack('<H', fmt[2:4])[0]
        sample_rate = struct.unpack('<I', fmt[4:8])[0]
        bits = struct.unpack('<H', fmt[14:16])[0]
        print(f"    PCM={audio_fmt}, ch={channels}, rate={sample_rate}, bits={bits}")
    elif chunk_id == b'data':
        print(f"    Audio data: {chunk_size} bytes")
        print(f"    Duration: {chunk_size / (sample_rate * channels * bits/8):.2f} seconds")
    elif chunk_id == b'LIST':
        list_data = reconstructed[offset+8:offset+8+chunk_size]
        list_type = list_data[0:4]
        print(f"    LIST type: '{list_type.decode('ascii', errors='replace')}'")
        # Parse sub-chunks
        loff = 4
        while loff < len(list_data) - 8:
            sub_id = list_data[loff:loff+4]
            sub_size = struct.unpack('<I', list_data[loff+4:loff+8])[0]
            sub_data = list_data[loff+8:loff+8+sub_size]
            print(f"      '{sub_id.decode('ascii', errors='replace')}': {repr(sub_data)}")
            loff += 8 + sub_size
    
    offset += 8 + chunk_size

# Extract ALL strings from the orphan data for flag hunting
print(f"\n\nALL STRINGS IN ORPHAN DATA:")
text = orphan_data.decode('ascii', errors='replace')
# Find all iCS-like patterns
import re
flag_patterns = re.findall(r'[iI][cC][sS]\{[^}]+\}', text)
if flag_patterns:
    print(f"Found ICS flags: {flag_patterns}")

# Look for any base64 or hex encoded strings
base64_pattern = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
if base64_pattern:
    print(f"Base64-like: {base64_pattern[:5]}")

# Show all non-gibberish text
for line in text.split('\n'):
    stripped = line.strip()
    if len(stripped) > 3 and any(c.isalpha() for c in stripped):
        if not all(c in '\x00\xff\xfe\xfd' for c in stripped):
            print(f"  {stripped[:120]}")
