import struct

with open('D:/test/CTF/The Final Rehearsal/rehearsal_laptop.E01', 'rb') as f:
    image_data = f.read()

bps = 512; spc = 8; reserved_sectors = 32; num_fats = 2; sectors_per_fat = 32
data_area_start = reserved_sectors + (num_fats * sectors_per_fat)
fat_offset = reserved_sectors * bps

# Follow the orphaned FAT chain from cluster 3
cluster = 3
orphan_data = b''
orphan_clusters = []
visited = set()

while cluster != 0x0FFFFFFF and cluster != 0 and cluster not in visited:
    visited.add(cluster)
    orphan_clusters.append(cluster)
    sector = data_area_start + (cluster - 2) * spc
    offset = sector * bps
    chunk = image_data[offset:offset + spc * bps]
    orphan_data += chunk
    
    fat_entry_offset = fat_offset + cluster * 4
    next_val = struct.unpack_from('<I', image_data, fat_entry_offset)[0]
    next_cluster = next_val & 0x0FFFFFFF
    cluster = next_cluster

print(f"Orphaned clusters: {orphan_clusters[:10]}... ({len(orphan_clusters)} total)")
print(f"Total orphan data: {len(orphan_data)} bytes")
print(f"\nFirst 500 bytes of orphan data:")
print(f"  Hex: {orphan_data[:500].hex()}")
print(f"\n  ASCII: {repr(orphan_data[:500])}")

# Try to decode as text
try:
    text = orphan_data.decode('ascii', errors='replace')
    # Show all printable portions
    lines = [line for line in text.split('\n') if line.strip()]
    print(f"\nDecoded text ({len(lines)} non-empty lines):")
    for line in lines[:100]:
        if any(c.isprintable() for c in line):
            print(f"  {line[:120]}")
except Exception as e:
    print(f"Decode error: {e}")

# Search for flag patterns in the orphan data
for pattern in [b'iCS{', b'ICS{', b'flag{', b'FLAG{', b'CTF{', b'ctf{']:
    idx = orphan_data.find(pattern)
    if idx >= 0:
        print(f"\n  FOUND '{pattern.decode()}' at offset {idx}")
        print(f"  Context: {repr(orphan_data[idx:idx+100])}")

# Search for the hex string or its ASCII representation
hex_bytes = bytes.fromhex("260d1637041e0414111f100b070608011e151d000c0909190a33")
idx = orphan_data.find(hex_bytes)
if idx >= 0:
    print(f"\n  FOUND hex pattern in orphan data at offset {idx}")
else:
    print("\n  Hex pattern not in orphan data")

# Look for interesting text
for term in [b'note', b'seal', b'locked', b'ONELASTLIGHT', b'rehearsal', b'FINAL', b'deliberate', b'accident']:
    idx = orphan_data.lower().find(term.lower())
    if idx >= 0:
        print(f"\n  Text '{term.decode()}' found at offset {idx}")
        print(f"  Context: {repr(orphan_data[max(0,idx-30):idx+len(term)+30])}")

# Save orphan data for further analysis
with open('C:/Users/Milindu/AppData/Local/Temp/kilo/orphan_data.bin', 'wb') as f:
    f.write(orphan_data)
print(f"\nSaved orphan data ({len(orphan_data)} bytes)")
