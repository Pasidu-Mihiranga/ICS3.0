import struct

with open('D:/test/CTF/The Final Rehearsal/rehearsal_laptop.E01', 'rb') as f:
    image_data = f.read()

bps = 512; spc = 8; reserved_sectors = 32; num_fats = 2; sectors_per_fat = 32
data_area_start = reserved_sectors + (num_fats * sectors_per_fat)
fat_offset = reserved_sectors * bps

cluster = 3; orphan = b''; visited = set()
while cluster != 0x0FFFFFFF and cluster != 0 and cluster not in visited:
    visited.add(cluster)
    sector = data_area_start + (cluster - 2) * spc
    orphan += image_data[sector * bps:sector * bps + spc * bps]
    next_cluster = struct.unpack_from('<I', image_data, fat_offset + cluster * 4)[0] & 0x0FFFFFFF
    cluster = next_cluster

data_size = struct.unpack_from('<I', orphan, 40)[0]
audio = orphan[44:44 + data_size]

# Method 1: Low byte of each 16-bit sample as ASCII
lo_ascii = bytes(audio[i] for i in range(0, len(audio)-1, 2))
for pat in [b'iCS{', b'ICS{', b'flag{']:
    idx = lo_ascii.find(pat)
    if idx >= 0:
        end = lo_ascii.find(b'}', idx)
        if end >= 0:
            print(f"LO_BYTE FLAG: {lo_ascii[idx:end+1].decode()}")

# Method 2: High byte (absolute) as ASCII
hi_ascii = bytes((struct.unpack_from('<h', audio, i)[0] >> 8) & 0x7F 
                 for i in range(0, len(audio)-1, 2))
hi_ascii_nozero = bytes(b for b in hi_ascii if b >= 32)
for pat in [b'iCS{', b'ICS{']:
    idx = hi_ascii_nozero.find(pat)
    if idx >= 0:
        end = hi_ascii_nozero.find(b'}', idx)
        if end >= 0:
            print(f"HI_BYTE FLAG: {hi_ascii_nozero[idx:end+1].decode()}")

# Method 3: Filter audio to get zero-crossing text
# When amplitude jumps significantly, extract the byte
text_bytes = bytearray()
prev_sample = 0
for i in range(0, len(audio)-1, 2):
    sample = struct.unpack_from('<h', audio, i)[0]
    diff = abs(sample - prev_sample)
    if diff > 500 and 32 <= (sample & 0xFF) <= 126:
        text_bytes.append(sample & 0xFF)
    prev_sample = sample

text_str = bytes(text_bytes)
for pat in [b'iCS{', b'ICS{']:
    idx = text_str.find(pat)
    if idx >= 0:
        end = text_str.find(b'}', idx)
        if end >= 0:
            print(f"SIGNAL FLAG: {text_str[idx:end+1].decode()}")

# Method 4: Concatenate every Nth byte
for step in [2, 3, 4, 5, 7, 10, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
    subset = bytes(audio[i] for i in range(0, min(len(audio), 10000), step))
    for pat in [b'iCS{', b'ICS{']:
        idx = subset.find(pat)
        if idx >= 0:
            end = subset.find(b'}', idx)
            if end >= 0:
                print(f"Step{step} FLAG: {subset[idx:end+1].decode()}")

# Method 5: Search the complete orphan data (including metadata) for flag
print(f"\nFull orphan search ({len(orphan)} bytes):")
for pat in [b'iCS{', b'ICS{', b'flag{', b'FLAG{', b'ctf{']:
    idx = orphan.find(pat)
    if idx >= 0:
        end = orphan.find(b'}', idx)
        if end >= 0:
            print(f"  FOUND: {orphan[idx:end+1].decode()}")
        else:
            print(f"  Found {pat} at {idx}, no closing brace")
            print(f"  Context: {repr(orphan[idx:idx+100])}")

# Method 6: Try simple audio-to-text via amplitude thresholding
print(f"\nAmplitude analysis (first 10000 samples):")
meaningful = []
for i in range(0, min(len(audio), 20000), 2):
    sample = struct.unpack_from('<h', audio, i)[0]
    if abs(sample) > 1000:
        meaningful.append((i//2, sample))
print(f"  {len(meaningful)} samples above threshold (>{1000})")
if meaningful:
    print(f"  First: idx={meaningful[0][0]}, amp={meaningful[0][1]}")
    print(f"  Last: idx={meaningful[-1][0]}, amp={meaningful[-1][1]}")

# Method 7: Look for repeating patterns / DTMF
# Check if audio has distinct frequency bands
print(f"\nSignal characteristics:")
# Calculate RMS
rms = (sum(s*s for i in range(0, min(len(audio), 20000), 2) 
           for s in [struct.unpack_from('<h', audio, i)[0]]) / 10000) ** 0.5
print(f"  RMS (first 10k samples): {rms:.1f}")

# Count zero crossings
zero_crossings = 0
prev = 0
for i in range(0, min(len(audio), 20000), 2):
    curr = struct.unpack_from('<h', audio, i)[0]
    if (prev >= 0 and curr < 0) or (prev < 0 and curr >= 0):
        zero_crossings += 1
    prev = curr
print(f"  Zero crossings (first 10k): {zero_crossings}")
print(f"  Estimated freq: {zero_crossings * 22050 / 10000:.0f} Hz")
