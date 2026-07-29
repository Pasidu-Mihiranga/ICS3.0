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

# Use spectrogram once for all window sizes
# nperseg = window size, noverlap = 0 for non-overlapping windows
for nperseg in [220, 200, 147, 294, 441]:
    f, t, Sxx = signal.spectrogram(samples, rate, nperseg=nperseg, noverlap=0, 
                                     nfft=max(2048, nperseg * 2))
    
    # Find indices for 495 and 1195 Hz
    idx_495 = np.argmin(np.abs(f - 495))
    idx_1195 = np.argmin(np.abs(f - 1195))
    
    # Compare power at each time
    bits = (Sxx[idx_1195, :] > Sxx[idx_495, :]).astype(np.uint8)
    
    zero_count = np.sum(bits == 0)
    one_count = np.sum(bits == 1)
    print(f"\nWin={nperseg}: {len(bits)} bits, 0:{zero_count} 1:{one_count}")
    print(f"  First 50: {''.join(str(b) for b in bits[:50])}")
    print(f"  Sample at t=30s: {''.join(str(b) for b in bits[30:80])}")
    
    n_bits = len(bits)
    for w in range(10, min(600, n_bits)):
        if n_bits % w == 0:
            h = n_bits // w
            if 0.3 <= h/w <= 3 and w >= 30:
                bits_list = bits.tolist()
                img_data = np.array(bits_list[:w*h]).reshape((h, w)) * 255
                img = Image.fromarray(img_data.astype(np.uint8))
                img.save(f"D:/test/CTF/7981/fsq_{nperseg}_{w}x{h}.png")
                print(f"  Image: {w}x{h}")

print("\nDone!")
