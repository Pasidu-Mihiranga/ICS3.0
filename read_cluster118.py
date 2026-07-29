import struct

with open('D:/test/CTF/The Final Rehearsal/rehearsal_laptop.E01', 'rb') as f:
    image_data = f.read()

bps = 512; spc = 8; reserved_sectors = 32; num_fats = 2; sectors_per_fat = 32
data_area_start = reserved_sectors + (num_fats * sectors_per_fat)
fat_offset = reserved_sectors * bps

# Read cluster 118 - the deleted Final_Rehearsal directory
sector = data_area_start + (118 - 2) * spc
offset = sector * bps
cluster_data = image_data[offset:offset + spc * bps]

print(f"Cluster 118 at sector {sector}, offset {offset}")
print(f"Size: {len(cluster_data)} bytes")
print(f"First 64 bytes hex: {cluster_data[:64].hex()}")
print()

# Parse directory entries
lfn_parts = []
i = 0
while i < len(cluster_data):
    entry = cluster_data[i:i+32]
    if entry[0] == 0:
        break
    
    if entry[11] & 0x0F == 0x0F:  # LFN entry
        seq = entry[0]
        name_chunk = entry[1:11] + entry[14:26] + entry[28:30]
        lfn_parts.append((seq, name_chunk))
        i += 32
        continue
    
    name = entry[0:11]
    is_deleted = (entry[0] == 0xE5)
    
    cluster_hi = struct.unpack_from('<H', entry, 20)[0]
    cluster_lo = struct.unpack_from('<H', entry, 26)[0]
    cluster = (cluster_hi << 16) | cluster_lo
    size = struct.unpack_from('<I', entry, 28)[0]
    attr = entry[11]
    is_dir = bool(attr & 0x10)
    
    # Build display name
    if is_deleted:
        sfn = b'\xe5' + entry[1:11]
    else:
        sfn = entry[0:11]
    
    sfn_str = sfn.decode('ascii', errors='replace').strip()
    
    # Reconstruct LFN
    lfn = ""
    if lfn_parts:
        sorted_parts = sorted(lfn_parts, key=lambda x: x[0] & 0x3F)
        for seq, chunk in sorted_parts:
            lfn += chunk.decode('utf-16-le', errors='replace')
        lfn = lfn.rstrip('\x00\xff')
    
    typ = "DIR" if is_dir else "FILE"
    status = "DELETED" if is_deleted else "ACTIVE"
    print(f"[{typ:5s}] [{status:7s}] cluster={cluster:6d} size={size:8d} SFN='{sfn_str}' LFN='{lfn}'")
    
    # If file has a real name, highlight it
    if lfn and not is_dir:
        print(f"       >>> REAL FILENAME = '{lfn}' <<<")
    
    lfn_parts = []
    i += 32

# Also dump hex of all entries for raw inspection
print(f"\n\nRaw directory entry dump (first 512 bytes):")
for row in range(0, min(512, len(cluster_data)), 32):
    entry = cluster_data[row:row+32]
    print(f"  {row:04X}: {entry.hex()}  |  {''.join(chr(b) if 32<=b<127 else '.' for b in entry)}")
