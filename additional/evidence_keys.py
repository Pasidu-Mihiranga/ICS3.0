import struct

with open('D:/test/CTF/The Final Rehearsal/rehearsal_laptop.E01', 'rb') as f:
    img = f.read()

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

hex_bytes = bytes.fromhex('260d1637041e0414111f100b070608011e151d000c0909190a33')

# Try evidence file content as keys (first 26 bytes)
evidence_keys = []

# STAGE_AC.CSV content
stage = read_clusters(img, 115, 521)[:521]
evidence_keys.append(('STAGE_AC.CSV content', stage[:26]))

# VOICE_NO.WAV audio data
orphan = read_clusters(img, 3)
audio = orphan[44:44+struct.unpack_from('<I', orphan, 40)[0]]
evidence_keys.append(('VOICE_NO.WAV audio', audio[:26]))

# WAV audio from offset 1000
evidence_keys.append(('VOICE audio[1000:1026]', audio[1000:1026]))

# WAV audio first non-silent (from sample 4932)
evidence_keys.append(('VOICE audio at speech start', audio[4932*2:4932*2+26]))

# REHEARSATXT content
reh = read_clusters(img, 125, 432)[:432]
evidence_keys.append(('REHEARSATXT content', reh[:26]))

# STAFF_DICSV content
staff = read_clusters(img, 128, 519)[:519]
evidence_keys.append(('STAFF_DICSV content', staff[:26]))

# LIGHTINGTXT content
light = read_clusters(img, 123, 439)[:439]
evidence_keys.append(('LIGHTINGTXT content', light[:26]))

# BROWSER_DB raw
browser = read_clusters(img, 126, 8192)[:8192]
evidence_keys.append(('BROWSER_DB raw', browser[:26]))

# Try each as XOR key
for name, key_data in evidence_keys:
    key = key_data[:26]
    result = bytes([a ^ b for a, b in zip(hex_bytes, key)])
    try:
        r = result.decode('ascii', errors='replace')
        has_flag = '{' in r and '}' in r
        printable = all(32 <= c <= 126 for c in result)
        marker = ' <-- FLAG!' if has_flag else (' (printable)' if printable else '')
        if has_flag or printable:
            print(f'{name}: {r}{marker}')
        else:
            print(f'{name}: (binary)')
    except:
        print(f'{name}: (decode error)')

# Also try: XOR with both ONELASTLIGHT (first 12) + evidence (next 14)
print('\n=== HYBRID KEYS ===')
hybrid_keys = [
    ('ONELASTLIGHT + STAGE_AC.CSV', b'ONELASTLIGHT' + stage[:14]),
    ('ONELASTLIGHT + VOICE.WAV', b'ONELASTLIGHT' + audio[:14]),
    ('ONELASTLIGHT + REHEARSATXT', b'ONELASTLIGHT' + reh[:14]),
    ('ONELASTLIGHT + STAFF', b'ONELASTLIGHT' + staff[:14]),
]
for name, key in hybrid_keys:
    if len(key) >= 26:
        key = key[:26]
    result = bytes([a ^ b for a, b in zip(hex_bytes, key)])
    try:
        r = result.decode('ascii', errors='replace')
        has_flag = '{' in r and '}' in r
        if has_flag:
            print(f'{name}: {r} <-- FLAG!')
        elif all(32 <= c <= 126 for c in result):
            print(f'{name}: {r}')
    except:
        pass
