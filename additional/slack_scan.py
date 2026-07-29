import struct

with open('D:/test/CTF/The Final Rehearsal/rehearsal_laptop.E01', 'rb') as f:
    image_data = f.read()

bps = 512; spc = 8; reserved_sectors = 32; num_fats = 2; sectors_per_fat = 32
data_area_start = reserved_sectors + (num_fats * sectors_per_fat)
fat_offset = reserved_sectors * bps

def read_cluster_chain_full(data, start_cluster):
    """Read full cluster chain, return raw bytes with cluster boundaries"""
    result = b''
    cluster = start_cluster
    clusters_used = []
    visited = set()
    while cluster != 0x0FFFFFFF and cluster != 0 and cluster not in visited:
        visited.add(cluster)
        sector = data_area_start + (cluster - 2) * spc
        offset = sector * bps
        result += data[offset:offset + spc * bps]
        clusters_used.append(cluster)
        next_cluster = struct.unpack_from('<I', data, fat_offset + cluster * 4)[0] & 0x0FFFFFFF
        cluster = next_cluster
    return result, clusters_used

# Known files with their clusters and sizes
files = [
    ("REHEARSATXT", 125, 432),
    ("BROWSER_DB", 126, 8192),
    ("STAFF_DICSV", 128, 519),
    ("LIGHTINGTXT", 123, 439),
    ("TRACK_01MP3", 119, 15368),
]

print("FILE SLACK SPACE ANALYSIS")
print("="*70)

for name, cluster, size in files:
    raw_data, clusters = read_cluster_chain_full(image_data, cluster)
    total_raw = len(raw_data)
    slack_size = total_raw - size
    print(f"\n{name}: cluster={cluster}, size={size}, raw={total_raw}, slack={slack_size}")
    
    if slack_size > 0:
        slack_data = raw_data[size:]
        # Check if slack contains non-zero data
        non_zero = slack_data.rstrip(b'\x00')
        if len(non_zero) > 0:
            print(f"  NON-ZERO SLACK FOUND! ({len(non_zero)} bytes)")
            print(f"  Hex: {non_zero[:200].hex()}")
            print(f"  ASCII: {repr(non_zero[:200])}")
            # Try to decode as text
            try:
                text = non_zero.decode('ascii', errors='replace')
                if any(c.isprintable() for c in text):
                    print(f"  Text: {text[:200]}")
            except:
                pass
        else:
            print(f"  Slack is all zeros")

# Also check free/unallocated clusters
# Get all used clusters from FAT
used_clusters = set()
# Scan FAT for non-zero entries
for c in range(2, 4096):  # 16MB / 4096 bytes per cluster = ~4096 clusters
    entry_offset = fat_offset + c * 4
    if entry_offset + 4 <= len(image_data):
        val = struct.unpack_from('<I', image_data, entry_offset)[0] & 0x0FFFFFFF
        if val != 0:  # Cluster is allocated
            used_clusters.add(c)

print(f"\n\nUNALLOCATED CLUSTERS:")
data_area_end = len(image_data) // (spc * bps)
for c in range(2, min(200, data_area_end)):
    if c not in used_clusters:
        sector = data_area_start + (c - 2) * spc
        offset = sector * bps
        if offset + spc * bps <= len(image_data):
            cluster_data = image_data[offset:offset + spc * bps]
            non_zero = cluster_data.rstrip(b'\x00')
            if len(non_zero) > 0:
                print(f"  Cluster {c}: {len(non_zero)} non-zero bytes")
                print(f"    Hex: {non_zero[:100].hex()}")
                print(f"    Text: {repr(non_zero[:100])}")

# Also dump the FAT for any interesting patterns
print(f"\n\nFAT TABLE DUMP (first 500 entries):")
for c in range(2, min(500, 4096)):
    entry_offset = fat_offset + c * 4
    val = struct.unpack_from('<I', image_data, entry_offset)[0] & 0x0FFFFFFF
    if val != 0 and val != 0x0FFFFFFF:
        print(f"  Cluster {c} -> {val}")

# Look for the exact hex string from the note IN the slack or unallocated space
print(f"\n\nSEARCHING FOR HEX PATTERN IN ENTIRE IMAGE...")
hex_bytes = bytes.fromhex("260d1637041e0414111f100b070608011e151d000c0909190a33")
for offset in range(0, len(image_data) - 26):
    if image_data[offset:offset+26] == hex_bytes:
        print(f"  FOUND at absolute offset {offset}, sector {offset//512}")
        break
else:
    print("  Not found anywhere in image")

# Also search for the hex as ASCII text (with spaces)
hex_text = b"26 0D 16 37 04 1E 04 14 11 1F 10 0B 07 06 08 01 1E 15 1D 00 0C 09 09 19 0A 33"
for offset in range(0, len(image_data) - len(hex_text)):
    if image_data[offset:offset+len(hex_text)] == hex_text:
        print(f"  FOUND as ASCII text at offset {offset}, sector {offset//512}")
        print(f"  Context: {repr(image_data[offset:offset+100])}")
        break
else:
    print("  Not found as ASCII text")
