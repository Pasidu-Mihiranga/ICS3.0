import struct, sqlite3

with open('D:/test/CTF/The Final Rehearsal/rehearsal_laptop.E01', 'rb') as f:
    img = f.read()

# Search UTF-16LE flag prefixes
for prefix_ascii in ['iCS{', 'ICS{', 'ics{']:
    prefix_utf16 = prefix_ascii.encode('utf-16-le')
    idx = img.find(prefix_utf16)
    if idx >= 0:
        print(f'UTF16-LE {prefix_ascii} at offset {idx}')
        ctx = img[idx:idx+200]
        for end in range(idx + len(prefix_utf16), min(len(img), idx + 200)):
            chunk = img[idx:end]
            try:
                text = chunk.decode('utf-16-le', errors='ignore')
                if '}' in text:
                    print(f'  TEXT: {text}')
                    break
            except:
                pass

# Search ASCII flag
print()
for i in range(len(img) - 30):
    if img[i:i+4] == b'iCS{' or img[i:i+4] == b'ICS{':
        print(f'ASCII flag at offset {i}')
        end = img.find(b'}', i)
        if end >= 0 and end - i < 100:
            print(f'  {img[i:end+1].decode("ascii", errors="replace")}')
        break

# Recover browser SQLite free pages
bps = 512; spc = 8; rs = 32; nf = 2; spf = 32
das = rs + (nf * spf); fo = rs * bps

def read_clusters(data, sc, max_size=None):
    r = b''; c = sc; v = set()
    while c != 0x0FFFFFFF and c != 0 and c not in v:
        v.add(c)
        s = das + (c - 2) * spc
        r += data[s * bps:s * bps + spc * bps]
        c = struct.unpack_from('<I', data, fo + c * 4)[0] & 0x0FFFFFFF
        if max_size and len(r) >= max_size:
            break
    return r

browser = read_clusters(img, 126, 8192)[:8192]
open('C:/Users/Milindu/AppData/Local/Temp/kilo/browser.sqlite', 'wb').write(browser)
conn = sqlite3.connect('C:/Users/Milindu/AppData/Local/Temp/kilo/browser.sqlite')
c = conn.cursor()

# Try to recover deleted data from SQLite
c.execute('PRAGMA freelist_count')
print(f'\nSQLite freelist: {c.fetchone()}')

# Search raw browser bytes for flag
for pat in [b'iCS{', b'ICS{', b'flag{']:
    idx = browser.find(pat)
    if idx >= 0:
        end = browser.find(b'}', idx)
        if end >= 0:
            print(f'Browser raw flag: {browser[idx:end+1].decode()}')

# Also scan the orphan voice note for any flag
orphan = read_clusters(img, 3)
for pat in [b'iCS{', b'ICS{', b'flag{']:
    idx = orphan.find(pat)
    if idx >= 0:
        end = orphan.find(b'}', idx)
        if end >= 0:
            print(f'Orphan WAV flag: {orphan[idx:end+1].decode()}')

# Scan STAFF_DICSV for flag
staff = read_clusters(img, 128, 519)[:519]
for pat in [b'iCS{', b'ICS{', b'flag{']:
    idx = staff.find(pat)
    if idx >= 0:
        end = staff.find(b'}', idx)
        if end >= 0:
            print(f'Staff CSV flag: {staff[idx:end+1].decode()}')

# Scan LIGHTINGTXT for flag
light = read_clusters(img, 123, 439)[:439]
for pat in [b'iCS{', b'ICS{', b'flag{']:
    idx = light.find(pat)
    if idx >= 0:
        end = light.find(b'}', idx)
        if end >= 0:
            print(f'Lighting TXT flag: {light[idx:end+1].decode()}')

# Scan REHEARSATXT for flag
reh = read_clusters(img, 125, 432)[:432]
for pat in [b'iCS{', b'ICS{', b'flag{']:
    idx = reh.find(pat)
    if idx >= 0:
        end = reh.find(b'}', idx)
        if end >= 0:
            print(f'Rehearsal TXT flag: {reh[idx:end+1].decode()}')

# Scan the STAGE_AC.CSV from cluster 115
stage = read_clusters(img, 115, 521)[:521]
for pat in [b'iCS{', b'ICS{', b'flag{']:
    idx = stage.find(pat)
    if idx >= 0:
        end = stage.find(b'}', idx)
        if end >= 0:
            print(f'Stage CSV flag: {stage[idx:end+1].decode()}')

# Final: search ENTIRE image for any iCS pattern, case insensitive
print('\nFull image byte scan for i/C/S brace:')
for i in range(len(img) - 40):
    if chr(img[i]) in 'iI' and chr(img[i+1]) in 'cC' and chr(img[i+2]) in 'sS' and img[i+3] == ord('{'):
        end = img.find(b'}', i)
        if end >= 0 and end - i < 50:
            flag = img[i:end+1].decode('ascii', errors='replace')
            print(f'  FOUND at {i}: {flag}')
