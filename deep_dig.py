import struct, sys
sys.path.insert(0, 'D:/test/CTF/.tools')
import exifread

# ========== 1. Extract and analyze photo thumbnail ==========
with open('D:/test/CTF/The Final Rehearsal/dressing_room.jpg', 'rb') as f:
    jpg_data = f.read()

tags = exifread.process_file(open('D:/test/CTF/The Final Rehearsal/dressing_room.jpg', 'rb'), details=True)

# Find and save the thumbnail
for k, v in tags.items():
    if 'Thumb' in k or 'thumbnail' in k:
        print(f'{k}: type={type(v).__name__}')
        if hasattr(v, 'values'):
            print(f'  values size: {len(v.values)}')

# JPEGInterchangeFormat = 458, JPEGInterchangeFormatLength = 15456
print(f'\nJPEG thumbnail at offset 458, length 15456')
thumb_data = jpg_data[458:458+15456]
with open('C:/Users/Milindu/AppData/Local/Temp/kilo/thumb.jpg', 'wb') as f:
    f.write(thumb_data)
print(f'Saved thumbnail ({len(thumb_data)} bytes)')

# Check thumbnail for hidden data
import subprocess
result = subprocess.run(['strings', '-n', '6', 'C:/Users/Milindu/AppData/Local/Temp/kilo/thumb.jpg'], capture_output=True, text=True)
print('\nThumbnail strings:')
for line in result.stdout.strip().split('\n')[:50]:
    if line.strip():
        print(f'  {line.strip()}')

# ========== 2. Examine MP3 binary structure ==========
with open('D:/test/CTF/The Final Rehearsal/rehearsal_laptop.E01', 'rb') as f:
    image_data = f.read()

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

mp3_data = read_cluster_chain(image_data, 119)[:15368]

print('\n' + '='*60)
print('MP3 DEEP ANALYSIS')
print('='*60)
print(f'Size: {len(mp3_data)}')

# Parse ID3v2 header
if mp3_data[:3] == b'ID3':
    id3_version = mp3_data[3:5]
    id3_flags = mp3_data[5]
    # ID3v2 size is synchsafe integer (4 bytes, only 7 bits per byte used)
    id3_size = 0
    for i in range(4):
        id3_size = (id3_size << 7) | mp3_data[6+i]
    print(f'ID3 version: {id3_version[0]}.{id3_version[1]}')
    print(f'ID3 flags: 0x{id3_flags:02X}')
    print(f'ID3 declared size: {id3_size}')
    
    # The actual content starts after the ID3 header (10 bytes)
    # If size is 0, there are no frames, but there's still data...
    print(f'\nData after ID3 header (first 300 bytes):')
    post_id3 = mp3_data[10:310]
    print(f'  Hex: {post_id3[:100].hex()}')
    print(f'  ASCII: {repr(post_id3[:200])}')
    
    # Check: is the data after ID3 actually an MPEG audio frame?
    # MPEG frame starts with 0xFF 0xFB or 0xFF 0xFA or 0xFF 0xF3 etc.
    print(f'\n  Looking for MPEG sync...')
    for offset in range(10, min(len(mp3_data), 2000)):
        if mp3_data[offset] == 0xFF and mp3_data[offset+1] & 0xE0 == 0xE0:
            print(f'  MPEG frame sync at offset {offset}')
            print(f'    Bytes: {mp3_data[offset:offset+4].hex()}')
            break
    
    # Look for any embedded file signatures in the MP3
    sigs = {
        b'PK\x03\x04': 'ZIP',
        b'\x89PNG': 'PNG',
        b'GIF8': 'GIF',
        b'\xff\xd8\xff': 'JPEG',
        b'%PDF': 'PDF',
        b'Rar!': 'RAR',
        b'\x1f\x8b\x08': 'GZIP',
        b'BZh': 'BZIP2',
    }
    for sig, name in sigs.items():
        idx = mp3_data.find(sig)
        if idx >= 0:
            print(f'\n  Found {name} signature at offset {idx}')

# ========== 3. Recursively scan all directories on E01 ==========
print('\n' + '='*60)
print('FULL DIRECTORY TREE SCAN')
print('='*60)

def parse_directory(data, path='/'):
    entries = []
    i = 0
    lfn_parts = []
    while i < len(data):
        entry = data[i:i+32]
        if entry[0] == 0:
            break
        if entry[11] & 0x0F == 0x0F:
            lfn_parts.append((entry[0], entry[1:11] + entry[14:26] + entry[28:30]))
            i += 32
            continue
        
        name = entry[0:11]
        is_deleted = (entry[0] == 0xE5)
        if is_deleted:
            name_display = '<DEL> ' + entry[1:11].decode('ascii', errors='replace').strip()
        else:
            name_display = name.decode('ascii', errors='replace').strip()
        
        cluster_hi = struct.unpack_from('<H', entry, 20)[0]
        cluster_lo = struct.unpack_from('<H', entry, 26)[0]
        cluster = (cluster_hi << 16) | cluster_lo
        size = struct.unpack_from('<I', entry, 28)[0]
        attr = entry[11]
        is_dir = bool(attr & 0x10)
        
        lfn = ''
        if lfn_parts:
            lfn_parts_sorted = sorted(lfn_parts, key=lambda x: x[0] & 0x3F)
            for seq, chunk in lfn_parts_sorted:
                lfn += chunk.decode('utf-16-le', errors='replace')
            lfn = lfn.rstrip('\x00\xff')
        
        if name_display not in ['.', '..']:
            full_path = path + '/' + name_display
            typ = 'DIR' if is_dir else 'FILE'
            print(f'  [{typ}] {full_path} cluster={cluster} size={size} is_del={is_deleted}')
            if is_dir and cluster != 0 and cluster != 124:
                dir_data = read_cluster_chain(image_data, cluster)
                parse_directory(dir_data, full_path)
        
        lfn_parts = []
        i += 32

# Parse root directory
root_dir = image_data[49152:49152 + 512 * 16]
parse_directory(root_dir)
