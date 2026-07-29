import struct

with open('D:/test/CTF/The Final Rehearsal/rehearsal_laptop.E01', 'rb') as f:
    img = f.read()

bps = 512; spc = 8; rs = 32; nf = 2; spf = 32
das = rs + (nf * spf); fo = rs * bps

def read_clusters(data, sc):
    r = b''; c = sc; v = set()
    while c != 0x0FFFFFFF and c != 0 and c not in v:
        v.add(c)
        s = das + (c - 2) * spc
        r += data[s * bps:s * bps + spc * bps]
        c = struct.unpack_from('<I', data, fo + c * 4)[0] & 0x0FFFFFFF
    return r

orphan = read_clusters(img, 3)
data_size = struct.unpack_from('<I', orphan, 40)[0]
audio = orphan[44:44 + data_size]

# Convert audio samples to their ABSOLUTE byte values, look for patterns
# Each 16-bit sample = 2 bytes, try both interpretations
samples_lo = []  # low byte of each sample
samples_hi = []  # high byte of each sample

for i in range(0, len(audio), 2):
    sample = struct.unpack_from('<h', audio, i)[0]
    samples_lo.append(sample & 0xFF)
    samples_hi.append((sample >> 8) & 0xFF)

# Look for 'iCS{' pattern in either byte stream
for name, stream in [('lo_byte', bytes(samples_lo)), ('hi_byte', bytes(samples_hi))]:
    for pat in [b'iCS{', b'ICS{']:
        idx = stream.find(pat)
        if idx >= 0:
            end = stream.find(b'}', idx)
            if end >= 0:
                print(f'{name} flag at sample {idx}: {stream[idx:end+1].decode()}')
            else:
                print(f'{name} partial at sample {idx}: {stream[idx:idx+50]}')

# Also try: absolute value of sample as ASCII (only taking samples where value is in ASCII range)
abs_samples = bytearray()
for i in range(0, len(audio), 2):
    sample = abs(struct.unpack_from('<h', audio, i)[0])
    val = sample & 0xFF
    if val >= 32 and val <= 126:
        abs_samples.append(val)

abs_str = bytes(abs_samples)
for pat in [b'iCS{', b'ICS{']:
    idx = abs_str.find(pat)
    if idx >= 0:
        end = abs_str.find(b'}', idx)
        if end >= 0:
            print(f'abs_ascii flag: {abs_str[idx:end+1].decode()}')
        else:
            print(f'abs_ascii partial: {abs_str[idx:idx+30]}')

# Try: difference between consecutive samples as values
diffs = bytearray()
prev = 0
for i in range(0, len(audio), 2):
    sample = struct.unpack_from('<h', audio, i)[0]
    diff = abs(sample - prev) & 0x7F
    if diff >= 32 and diff <= 126:
        diffs.append(diff)
    prev = sample

diffs_str = bytes(diffs)
for pat in [b'iCS{', b'ICS{']:
    idx = diffs_str.find(pat)
    if idx >= 0:
        end = diffs_str.find(b'}', idx)
        if end >= 0:
            print(f'diff flag: {diffs_str[idx:end+1].decode()}')

# Also try reading the VOICE_NO.WAV file's full name and using that as part of the key
# The real file name was "VOICE_NO.WAV" (from the directory entry)
# Try XOR hex with "VOICE_NO" padded to 26
hex_bytes = bytes.fromhex('260d1637041e0414111f100b070608011e151d000c0909190a33')
for key_name in [b'VOICE_NO', b'STAGE_AC', b'FINAL_RE']:
    key = (key_name * 10)[:26]
    result = bytes([a ^ b for a, b in zip(hex_bytes, key)])
    try:
        r = result.decode('ascii', errors='replace')
        if '{' in r and '}' in r:
            print(f'\nKey "{key_name.decode()}": {r} <-- FLAG!')
        elif all(32 <= c <= 126 for c in result):
            print(f'\nKey "{key_name.decode()}": {r}')
    except:
        pass

# FINAL IDEA: what if the XOR uses a key from the voice note METADATA?
# The LIST INFO says INAM = "VOICE_NOTE_FINAL"
# Try that as key
key = (b'VOICE_NOTE_FINAL' * 3)[:26]
result = bytes([a ^ b for a, b in zip(hex_bytes, key)])
try:
    r = result.decode('ascii', errors='replace')
    print(f'\nKey "VOICE_NOTE_FINAL": {r}')
except:
    pass

# Try the full stage CSV header as key
stage = read_clusters(img, 115, 521)[:521]
print(f'\nStage CSV header: {stage[:60]}')
# Use: timestamp_utc,badge_id,name,zone,event,workstation 
# That's 52 chars. First 26: "timestamp_utc,badge_id,na"
key = stage[:26]
result = bytes([a ^ b for a, b in zip(hex_bytes, key)])
print(f'Hex XOR Stage header: {result.hex()}')
print(f'  ASCII: {result}')
