import numpy as np
import struct
from scipy import signal
from PIL import Image

with open('D:/test/CTF/7981/7981/0.wav', 'rb') as f:
    raw = f.read()

pos = 12; rate = 44100
while pos < len(raw) - 8:
    chunk_id = raw[pos:pos+4]
    chunk_size = struct.unpack_from('<I', raw, pos+4)[0]
    if chunk_id == b'data':
        audio = raw[pos+8:pos+8+chunk_size]
        break
    pos += 8 + chunk_size

samples = np.frombuffer(audio, dtype=np.int16).astype(np.float64)
n = len(samples)
print(f"Samples: {n}, Duration: {n/rate:.2f}s")

# Efficient approach: Use FFT to detect frequencies at each time window
# Pre-compute frequency bins of interest
# Window size = 220 (44100/200 = 220.5)
win = 220
n_windows = n // win
print(f"Windows: {n_windows} (win size={win})")

# Process in chunks for memory efficiency
bits = np.zeros(n_windows, dtype=np.uint8)
chunk_size = 500  # Process 500 windows at a time

for chunk_start in range(0, n_windows, chunk_size):
    chunk_end = min(chunk_start + chunk_size, n_windows)
    
    for i in range(chunk_start, chunk_end):
        start = i * win
        chunk = samples[start:start+win]
        # Use scipy's FFT
        fft = np.abs(np.fft.rfft(chunk * np.hanning(win)))
        freqs = np.fft.rfftfreq(win, 1/rate)
        
        # Check power at 495 and 1195 Hz
        idx_495 = np.argmin(np.abs(freqs - 495))
        idx_1195 = np.argmin(np.abs(freqs - 1195))
        bits[i] = 1 if fft[idx_1195] > fft[idx_495] else 0

zero_count = np.sum(bits == 0)
one_count = np.sum(bits == 1)
print(f"Bits: {n_windows}, 0:{zero_count} 1:{one_count}")
print(f"First 100 bits: {''.join(str(b) for b in bits[:100])}")

# Try to form images
bit_list = bits.tolist()
n_bits = len(bit_list)

# Try all factor pairs within reasonable range
print("\n=== Image dimension candidates ===")
for w in range(10, min(500, n_bits)):
    if n_bits % w == 0:
        h = n_bits // w
        if 0.3 <= h/w <= 3 and w >= 10:
            print(f"  {w}x{h} (AR={h/w:.2f})")
            img_data = np.array(bit_list[:w*h]).reshape((h, w)) * 255
            img = Image.fromarray(img_data.astype(np.uint8))
            img.save(f"D:/test/CTF/7981/fsq_{w}x{h}.png")

# Also try other window sizes
for win2 in [147, 200, 294, 441]:
    n_win2 = n // win2
    bits2 = np.zeros(n_win2, dtype=np.uint8)
    for i in range(0, n_win2, 500):
        for j in range(i, min(i+500, n_win2)):
            start = j * win2
            chunk = samples[start:start+win2]
            fft = np.abs(np.fft.rfft(chunk * np.hanning(win2)))
            freqs = np.fft.rfftfreq(win2, 1/rate)
            idx_495 = np.argmin(np.abs(freqs - 495))
            idx_1195 = np.argmin(np.abs(freqs - 1195))
            bits2[j] = 1 if fft[idx_1195] > fft[idx_495] else 0
    
    z2 = np.sum(bits2 == 0)
    o2 = np.sum(bits2 == 1)
    print(f"\nWin={win2}: {n_win2} bits, 0:{z2} 1:{o2}")
    bl2 = bits2.tolist()
    for w in range(10, min(500, n_win2)):
        if n_win2 % w == 0:
            h = n_win2 // w
            if 0.3 <= h/w <= 3:
                img_data = np.array(bl2[:w*h]).reshape((h, w)) * 255
                img = Image.fromarray(img_data.astype(np.uint8))
                img.save(f"D:/test/CTF/7981/fsq_{win2}_{w}x{h}.png")

print("\nDone!")
