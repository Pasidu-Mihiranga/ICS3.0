import struct

with open('D:/test/CTF/The Final Rehearsal/rehearsal_laptop.E01', 'rb') as f:
    image_data = f.read()

bps = 512; spc = 8; reserved_sectors = 32; num_fats = 2; sectors_per_fat = 32
data_area_start = reserved_sectors + (num_fats * sectors_per_fat)
fat_offset = reserved_sectors * bps
total_sectors = len(image_data) // bps

# Search for the hex pattern from the investigator note anywhere in the image
hex_pattern = bytes.fromhex("260d1637041e0414111f100b070608011e151d000c0909190a33")
idx = image_data.find(hex_pattern)
if idx >= 0:
    print(f"Found hex pattern at offset {idx} (sector {idx//bps})")
else:
    print("Hex pattern not found in disk image")

# Search for "locked" or "note" in the image
for term in [b"locked note", b"Locked Note", b"LOCKED NOTE", b"seal", b"SEAL", b"case seal"]:
    idx = image_data.find(term)
    if idx >= 0:
        print(f"Found '{term.decode()}' at offset {idx}")

# Search for flag-like patterns in the image
for pattern in [b"iCS{", b"ICS{", b"flag{", b"FLAG{"]:
    idx = image_data.find(pattern)
    if idx >= 0:
        print(f"Found '{pattern.decode()}' at offset {idx}")
        end = idx + 100
        print(f"  Context: {repr(image_data[idx:end])}")

# Search for the hex string as text representation in the image
for s in [b"26 0D 16 37", b"26 0d 16 37"]:
    idx = image_data.find(s)
    if idx >= 0:
        print(f"Found hex text at offset {idx}")
        print(f"  Context: {repr(image_data[idx:idx+100])}")

# Also search for "ONELASTLIGHT" in the disk image (not just the EXIF)
for s in [b"ONELASTLIGHT", b"onelastlight", b"OneLastLight"]:
    idx = image_data.find(s)
    if idx >= 0:
        print(f"Found '{s.decode()}' at offset {idx}")
        print(f"  Sector: {idx//bps}")

# Look for any hidden text in free space / slack space
# Check the FAT for clues
print(f"\nTotal sectors: {total_sectors}")
print(f"Data area start sector: {data_area_start}")
print(f"Used clusters: up to about sector {(data_area_start + (128) * spc)}")
print(f"Free space starts around sector {(data_area_start + (128) * spc)}")
free_space = image_data[(data_area_start + 130 * spc) * bps:]
nonzero_free = free_space.rstrip(b'\x00')
print(f"Non-zero bytes in free space: {len(nonzero_free)}")
if len(nonzero_free) > 0:
    print(f"  First 200 bytes: {repr(nonzero_free[:200])}")
