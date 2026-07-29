import numpy as np
import struct
from PIL import Image

with open('D:/test/CTF/7981/7981/0.wav', 'rb') as f:
    raw = f.read()

pos = 12
while pos < len(raw) - 8:
    chunk_id = raw[pos:pos+4]
    chunk_size = struct.unpack_from('<I', raw, pos+4)[0]
    if chunk_id == b'data':
        audio_offset = pos + 8
        audio_size = chunk_size
        break
    pos += 8 + chunk_size

audio_data = raw[audio_offset:audio_offset + audio_size]
samples = np.frombuffer(audio_data, dtype=np.int16).astype(np.float64)
rate = 44100
total_dur = len(samples) / rate

print(f"Samples: {len(samples)}, Rate: {rate}, Duration: {total_dur:.4f}s")

# Goertzel for frequency detection
def goertzel_power(s, target_freq, sample_rate):
    s = s.astype(np.float64)
    N = len(s)
    k = int(0.5 + N * target_freq / sample_rate)
    omega = 2 * np.pi * k / N
    coeff = 2 * np.cos(omega)
    s_prev = 0.0
    s_prev2 = 0.0
    for sample in s:
        s_curr = sample + coeff * s_prev - s_prev2
        s_prev2 = s_prev
        s_prev = sample
    return s_prev2**2 + s_prev**2 - coeff * s_prev * s_prev2

# Try various window sizes for FSK decoding
print("\n=== FSK Decoding with various windows ===")
print("Window(samples) | Window(s) | Bits  | Bitrate | %0  | %1")
print("-" * 70)

best_results = []
for win_samples in [110, 147, 200, 220, 294, 441, 735, 882, 1102, 1470, 2205, 4410]:
    bits = []
    for start in range(0, len(samples) - win_samples, win_samples):
        chunk = samples[start:start+win_samples]
        p_495 = goertzel_power(chunk, 495, rate)
        p_1195 = goertzel_power(chunk, 1195, rate)
        bits.append(1 if p_1195 > p_495 else 0)
    
    zero_count = sum(1 for b in bits if b == 0)
    one_count = len(bits) - zero_count
    bitrate = len(bits) / total_dur
    
    print(f"{win_samples:14d} | {win_samples/rate:.3f}s    | {len(bits):5d} | {bitrate:7.2f} | {zero_count/len(bits)*100:4.1f} | {one_count/len(bits)*100:4.1f}")
    
    best_results.append((win_samples, bits, bitrate))

# Try to form images from decoded bits
print("\n=== Trying to form images ===")

# For each bitrate, try common image dimensions
for win_samples, bits, bitrate in best_results:
    n_bits = len(bits)
    
    # Try factorization
    factors = []
    for w in range(10, n_bits):
        if n_bits % w == 0:
            h = n_bits // w
            if 1 <= h / w <= 20:  # Reasonable aspect ratio
                factors.append((w, h, h/w))
    
    if factors:
        print(f"\nWin={win_samples} ({win_samples/rate:.4f}s), Bits={n_bits}:")
        for w, h, ar in factors[:10]:
            print(f"  Dimensions: {w}x{h} (AR={ar:.2f})")
            # Form image
            img_data = np.array(bits[:w*h]).reshape((h, w)) * 255
            img = Image.fromarray(img_data.astype(np.uint8))
            img.save(f"D:/test/CTF/7981/fsq_{win_samples}_{w}x{h}.png")

# Also try specific dimensions: 79x81 hint?
print("\n=== Trying dimension hints ===")
# 7981 = 23 * 347 (prime factorization!)
# Or 79 x 81?
# Or maybe the sample rate / 200 = 220.5 = window size

# Let's try window=220 (44100/200=220.5, maybe rounded to 220)
win = 220
bits_220 = []
for start in range(0, len(samples) - win, win):
    chunk = samples[start:start+win]
    p_495 = goertzel_power(chunk, 495, rate)
    p_1195 = goertzel_power(chunk, 1195, rate)
    bits_220.append(1 if p_1195 > p_495 else 0)

n = len(bits_220)
print(f"Window=220: {n} bits")

# Try 79x? 
# 31996 bits: 31996 = 4 * 7999 = 2*2*19*421
# Factors of 31996
for w in [19, 23, 38, 46, 73, 76, 79, 81, 92, 146, 158, 162, 292, 316, 347, 421, 694, 842, 1388, 1684]:
    if n % w == 0:
        h = n // w
        print(f"  {w}x{h}: testing...")
        img_data = np.array(bits_220[:w*h]).reshape((h, w)) * 255
        img = Image.fromarray(img_data.astype(np.uint8))
        img.save(f"D:/test/CTF/7981/fsq_220_{w}x{h}.png")

# Also try window 200 directly (200 samples = 200 bits at 220.5 Hz? No...)
# 200 samples per bit would give 35196 bits
win200 = 200
bits_200 = []
for start in range(0, len(samples) - win200, win200):
    chunk = samples[start:start+win200]
    p_495 = goertzel_power(chunk, 495, rate)
    p_1195 = goertzel_power(chunk, 1195, rate)
    bits_200.append(1 if p_1195 > p_495 else 0)

n200 = len(bits_200)
print(f"\nWindow=200: {n200} bits")
for w in [19, 23, 73, 79, 81, 146, 347, 421, 694, 842]:
    if n200 % w == 0:
        h = n200 // w
        img_data = np.array(bits_200[:w*h]).reshape((h, w)) * 255
        img = Image.fromarray(img_data.astype(np.uint8))
        img.save(f"D:/test/CTF/7981/fsq_200_{w}x{h}.png")
        print(f"  Saved {w}x{h}")

# Also try specific image from all bits aligned to 200bps
bps = 200
total_bits_from_200bps = int(total_dur * bps)
print(f"\nAt 200 bps, total bits would be: {total_bits_from_200bps}")
# Factors
for w in range(10, 500):
    if total_bits_from_200bps % w == 0:
        h = total_bits_from_200bps // w
        if 0.5 <= h/w <= 3:
            print(f"  Possible: {w}x{h}")
