import struct
import numpy as np
import collections

with open('D:/test/CTF/7981/7981/0.wav', 'rb') as f:
    raw = f.read()

pos = 12
while pos < len(raw) - 8:
    chunk_id = raw[pos:pos+4]
    chunk_size = struct.unpack_from('<I', raw, pos+4)[0]
    if chunk_id == b'data':
        audio = raw[pos+8:pos+8+chunk_size]
        break
    pos += 8 + chunk_size

samples = np.frombuffer(audio, dtype=np.int16)
lsb_bits = ''.join(str(s & 1) for s in samples)
lsb_bytes = bytearray()
for i in range(0, len(lsb_bits) - 7, 8):
    lsb_bytes.append(int(lsb_bits[i:i+8], 2))

print(f'Total LSB bytes: {len(lsb_bytes)}')
print(f'First 100 bytes hex: {lsb_bytes[:100].hex()}')
print(f'First 100 bytes raw: {repr(bytes(lsb_bytes[:100]))}')

for sig, name in [(b'PK\x03\x04', 'ZIP'), (b'PK\x05\x06', 'ZIP EOCD'),
                   (b'\x89PNG', 'PNG'), (b'\xff\xd8\xff', 'JPEG'), (b'GIF8', 'GIF'),
                   (b'Rar!', 'RAR'), (b'\x1f\x8b', 'GZIP'), (b'BZh', 'BZ2'),
                   (b'7z\xbc\xaf', '7Z')]:
    idx = lsb_bytes.find(sig)
    if idx >= 0:
        print(f'FOUND {name} signature at offset {idx}!')

text = lsb_bytes.decode('ascii', errors='replace')
for pattern in ['iCS{', 'ICS{', 'flag{', 'FLAG{', 'CTF{', 'password', 'pass', 'key', 'archiv']:
    idx = text.lower().find(pattern.lower())
    if idx >= 0:
        ctx = text[max(0,idx-10):idx+60]
        print(f'Found "{pattern}" at {idx}: ...{repr(ctx)}...')

freqs = collections.Counter(lsb_bytes)
print(f'\nByte freq top 20: {freqs.most_common(20)}')
print(f'Unique bytes: {len(freqs)}')
print(f'00 count: {freqs.get(0,0)}, FF count: {freqs.get(255,0)}')
print(f'ASCII printable ratio: {sum(1 for b in lsb_bytes if 32<=b<127)/len(lsb_bytes)*100:.1f}%')

# Write the full LSB data
with open('D:/test/CTF/7981/lsb_extracted.bin', 'wb') as f:
    f.write(lsb_bytes)
print(f'\nSaved full LSB data to lsb_extracted.bin ({len(lsb_bytes)} bytes)')
