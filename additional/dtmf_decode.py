import struct
import numpy as np
from scipy.fft import fft, fftfreq
from scipy.signal import find_peaks
import sys
sys.path.insert(0, 'D:/test/CTF/.tools')

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
audio_raw = orphan[44:44 + data_size]
sample_rate = 22050

# DTMF frequency pairs
dtmf = {
    '1': (697, 1209), '2': (697, 1336), '3': (697, 1477), 'A': (697, 1633),
    '4': (770, 1209), '5': (770, 1336), '6': (770, 1477), 'B': (770, 1633),
    '7': (852, 1209), '8': (852, 1336), '9': (852, 1477), 'C': (852, 1633),
    '*': (941, 1209), '0': (941, 1336), '#': (941, 1477), 'D': (941, 1633),
}

# Decode DTMF: process audio in windows, find dominant frequencies
window_size = int(sample_rate * 0.04)  # 40ms windows
step = window_size // 2
results = []

for start in range(0, len(audio_raw) - window_size * 2, step):
    window = np.array([struct.unpack_from('<h', audio_raw, i)[0] 
                       for i in range(start, start + window_size * 2, 2)], dtype=np.float64)
    
    if np.max(np.abs(window)) < 800:  # Skip silence
        continue
    
    # FFT
    n = len(window)
    yf = fft(window)
    xf = fftfreq(n, 1/sample_rate)[:n//2]
    magnitude = 2.0/n * np.abs(yf[:n//2])
    
    # Find peaks
    peaks, props = find_peaks(magnitude, height=np.max(magnitude)*0.3, distance=50)
    
    if len(peaks) >= 2:
        peak_freqs = sorted(xf[peaks[np.argsort(magnitude[peaks])[-3:]]])
        
        # Match to DTMF
        for digit, (f1, f2) in dtmf.items():
            found_f1 = any(abs(f - f1) < 25 for f in peak_freqs)
            found_f2 = any(abs(f - f2) < 25 for f in peak_freqs)
            if found_f1 and found_f2:
                results.append((start / sample_rate, digit))
                break

# Print decoded DTMF
print("DTMF Decoded:")
current_seq = []
last_time = -1
for t, digit in results:
    if last_time < 0 or t - last_time < 0.2:
        current_seq.append(digit)
    else:
        if current_seq:
            print(f"  {''.join(current_seq)} at ~{last_time:.1f}s")
        current_seq = [digit]
    last_time = t
if current_seq:
    print(f"  {''.join(current_seq)} at ~{last_time:.1f}s")

# Also try: extract the hex string directly from the DTMF
all_digits = [d for _, d in results]
dtmf_hex = ''.join(all_digits)
print(f"\nAll DTMF digits: {dtmf_hex}")

# Check if DTMF contains the hex from the note
hex_from_note = "260D1637041E0414111F100B070608011E151D000C0909190A33"
if hex_from_note in dtmf_hex.upper():
    print("  MATCHES the hex from investigator note!")
else:
    # Check partial matches
    match_count = 0
    for c in hex_from_note:
        if c.upper() in dtmf_hex:
            match_count += 1
    print(f"  {match_count}/{len(hex_from_note)} chars match")

# ALSO: Search PCAP more thoroughly for hidden data
print("\n\n=== PCAP DEEP SEARCH ===")
with open('D:/test/CTF/The Final Rehearsal/backstage_traffic.pcap', 'rb') as f:
    pcap = f.read()

# Look for any flag-like patterns
for pat in [b'iCS{', b'ICS{', b'flag{', b'FLAG{']:
    idx = pcap.find(pat)
    if idx >= 0:
        end = pcap.find(b'}', idx)
        print(f"  Found {pat} at {idx}, context: {repr(pcap[idx:idx+50])}")

# Look for the hex string as text in the PCAP  
for text_variant in [b'260D16', b'26 0D 16', b'26-0D-16']:
    idx = pcap.find(text_variant)
    if idx >= 0:
        print(f"  Hex text at {idx}: {repr(pcap[idx:idx+50])}")

# Extract any non-printable data that might be encoded
print(f"\n  PCAP size: {len(pcap)}")
# All unique byte values in PCAP
print(f"  Unique bytes: {sorted(set(pcap))[:50]}")
