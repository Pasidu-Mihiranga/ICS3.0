import struct, re

with open('D:/test/CTF/The Final Rehearsal/rehearsal_laptop.E01', 'rb') as f:
    image_data = f.read()

# Search for hex string as text (with and without spaces)
patterns = [
    b"26 0D 16 37",
    b"26 0d 16 37",
    b"260D1637",
    b"26-0D-16-37",
    b"260d1637041e0414111f100b070608011e151d000c0909190a33",
]

for pat in patterns:
    idx = image_data.find(pat)
    if idx >= 0:
        print(f"Found pattern: {pat} at offset {idx}")
    else:
        print(f"Pattern not found: {pat}")

# Search for any text containing "note" in various contexts
for term in [b"ote", b"locked", b"seal", b"mark", b"darkness", b"light or the other", b"leaves a mark"]:
    idx = image_data.find(term)
    if idx >= 0:
        print(f"Found '{term.decode()}' at {idx}, sector {idx//512}")
        start = max(0, idx-50)
        end = min(len(image_data), idx+100)
        print(f"  Context: {repr(image_data[start:end][:200])}")

# Re-read the SQLite DB with more detail
bps = 512; spc = 8; reserved_sectors = 32; num_fats = 2; sectors_per_fat = 32
data_area_start = reserved_sectors + (num_fats * sectors_per_fat)
fat_offset = reserved_sectors * bps

def read_cluster_chain(data, start_cluster):
    result = b''
    cluster = start_cluster
    visited = set()
    while cluster != 0x0FFFFFFF and cluster != 0 and cluster not in visited:
        visited.add(cluster)
        sector = data_area_start + (cluster - 2) * spc
        offset = sector * bps
        result += data[offset:offset + spc * bps]
        next_cluster = struct.unpack_from('<I', data, fat_offset + cluster * 4)[0] & 0x0FFFFFFF
        cluster = next_cluster
    return result

# Save and analyze SQLite
browser_data = read_cluster_chain(image_data, 126)[:8192]
with open('C:/Users/Milindu/AppData/Local/Temp/kilo/browser.sqlite', 'wb') as f:
    f.write(browser_data)

import sqlite3
conn = sqlite3.connect('C:/Users/Milindu/AppData/Local/Temp/kilo/browser.sqlite')
cur = conn.cursor()

# List ALL tables
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cur.fetchall()
print("\n=== Full SQLite DB Analysis ===")
print(f"Tables: {tables}")

for table in tables:
    table_name = table[0]
    # Get column info
    cur.execute(f"PRAGMA table_info([{table_name}])")
    cols = cur.fetchall()
    print(f"\n  Table '{table_name}' columns: {[c[1] for c in cols]}")
    
    cur.execute(f"SELECT * FROM [{table_name}]")
    rows = cur.fetchall()
    for i, row in enumerate(rows):
        print(f"    Row {i}: {row}")

conn.close()

# Also examine the MP3 tags
track_data = read_cluster_chain(image_data, 119)[:15368]
print(f"\n=== MP3 Analysis ===")
print(f"Size: {len(track_data)}")
print(f"First 200 bytes: {track_data[:200]}")

# Search for ID3 tags that might contain hidden info
# ID3v2 header: "ID3" + version + flags + size
if track_data[:3] == b'ID3':
    print("ID3v2 header found")
    # Parse frames
    offset = 10  # After ID3 header
    while offset < len(track_data) and track_data[offset:offset+4] != b'\x00\x00\x00\x00':
        frame_id = track_data[offset:offset+4].decode('ascii', errors='replace')
        if not frame_id.isprintable() or not frame_id[0].isalpha():
            break
        size = struct.unpack_from('>I', track_data, offset+4)[0]
        if size > 1000000 or size < 1:
            break
        frame_data = track_data[offset+10:offset+10+size]
        print(f"  Frame: {frame_id}, size={size}")
        if frame_id in ['TIT2', 'TALB', 'TPE1', 'TCOM', 'COMM', 'TXXX', 'USLT', 'APIC']:
            print(f"    Data: {repr(frame_data[:100])}")
        offset += 10 + size
