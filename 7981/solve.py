import struct
import numpy as np

with open('D:/test/CTF/7981/7981/0.wav', 'rb') as f:
    raw = f.read()

# Parse chunks
pos = 12
chunks = {}
audio_offset = None
audio_size = None
while pos < len(raw) - 8:
    chunk_id = raw[pos:pos+4]
    chunk_size = struct.unpack_from('<I', raw, pos+4)[0]
    if chunk_id == b'fmt ':
        rate = struct.unpack_from('<I', raw, pos+12)[0]
        ch = struct.unpack_from('<H', raw, pos+10)[0]
        bits = struct.unpack_from('<H', raw, pos+22)[0]
        print(f"fmt: rate={rate}, ch={ch}, bits={bits}")
    elif chunk_id == b'LIST':
        list_data = raw[pos+8:pos+8+chunk_size]
        print(f"LIST ({chunk_size}B): {list_data}")
    elif chunk_id == b'data':
        audio_offset = pos + 8
        audio_size = chunk_size
        print(f"data: {chunk_size}B at offset {audio_offset}")
    pos += 8 + chunk_size

audio_data = raw[audio_offset:audio_offset + audio_size]
samples = np.frombuffer(audio_data, dtype=np.int16)
print(f"\nTotal samples: {len(samples)}, duration: {len(samples)/rate:.2f}s")

# ============ APPROACH 1: LSB Steganography ============
print("\n=== APPROACH 1: LSB Steganography ===")
lsb_bits = ''.join(str(s & 1) for s in samples)
lsb_bytes = bytearray()
for i in range(0, len(lsb_bits) - 7, 8):
    lsb_bytes.append(int(lsb_bits[i:i+8], 2))

print(f"LSB decoded: {len(lsb_bytes)} bytes")
print(f"First 200 LSB bytes (hex): {lsb_bytes[:200].hex()}")
print(f"First 200 LSB bytes (ascii): {repr(lsb_bytes[:200])}")

# Check if LSB forms a valid image header
for header in [b'\x89PNG', b'\xff\xd8\xff', b'GIF8', b'BM']:
    idx = lsb_bytes.find(header)
    if idx >= 0:
        print(f"FOUND {header.hex()} at LSB offset {idx}!")
        end_markers = {b'\x89PNG': b'IEND', b'\xff\xd8\xff': b'\xff\xd9', b'GIF8': b'\x00;'}
        end = lsb_bytes.find(end_markers.get(header, b''), idx)
        if end >= 0:
            extracted = lsb_bytes[idx:end+4]
            ext = {b'\x89PNG': '.png', b'\xff\xd8\xff': '.jpg', b'GIF8': '.gif', b'BM': '.bmp'}
            fname = f'D:/test/CTF/7981/lsb_extracted{ext.get(header, ".bin")}'
            with open(fname, 'wb') as f:
                f.write(extracted)
            print(f"Saved to {fname} ({len(extracted)} bytes)")

# Search for flag patterns in LSB
for pattern in [b'iCS{', b'ICS{', b'flag{', b'FLAG{', b'CTF{']:
    idx = lsb_bytes.find(pattern)
    if idx >= 0:
        end = lsb_bytes.find(b'}', idx)
        if end >= 0:
            print(f"FLAG IN LSB: {lsb_bytes[idx:end+1].decode('ascii', errors='replace')}")

# ============ APPROACH 2: FSK/Binary Decoding ============
print("\n=== APPROACH 2: FSK Decoding (495Hz=0, 1195Hz=1) ===")

# Try different bit durations
for bit_dur_samples in [4410, 8820, 11025, 22050, 44100]:
    bits = []
    for i in range(0, len(samples) - bit_dur_samples, bit_dur_samples):
        chunk = samples[i:i+bit_dur_samples]
        # Goertzel for 495Hz and 1195Hz
        for freq in [495, 1195]:
            N = len(chunk)
            k = int(0.5 + N * freq / rate)
            omega = 2 * np.pi * k / N
            coeff = 2 * np.cos(omega)
            s_prev = 0
            s_prev2 = 0
            for s_val in chunk:
                s_curr = s_val + coeff * s_prev - s_prev2
                s_prev2 = s_prev
                s_prev = s_curr
            power = s_prev2**2 + s_prev**2 - coeff * s_prev * s_prev2
            if freq == 495:
                p_low = power
            else:
                p_high = power
        bits.append(0 if p_low > p_high else 1)
    
    # Convert to bytes
    bit_str = ''.join(str(b) for b in bits)
    result_bytes = bytearray()
    for i in range(0, len(bit_str) - 7, 8):
        result_bytes.append(int(bit_str[i:i+8], 2))
    
    zero_cnt = sum(1 for b in bits if b == 0)
    one_cnt = sum(1 for b in bits if b == 1)
    print(f"Bit dur={bit_dur_samples} ({bit_dur_samples/rate:.3f}s): {len(bits)} bits, 0:{zero_cnt} 1:{one_cnt}, first 20: {bits[:20]}")
    
    # Check for flags
    for pattern in [b'iCS{', b'ICS{', b'flag{']:
        idx = result_bytes.find(pattern)
        if idx >= 0:
            end = result_bytes.find(b'}', idx)
            if end >= 0:
                print(f"  FLAG: {result_bytes[idx:end+1].decode('ascii', errors='replace')}")

# ============ APPROACH 3: Spectrogram as Image ============
print("\n=== APPROACH 3: Spectrogram Visualization ===")
from scipy import signal

# High-res spectrogram
f, t_spec, Sxx = signal.spectrogram(samples.astype(np.float32) / 32768.0, rate,
                                      nperseg=512, noverlap=256, nfft=1024)
# Convert to image (log scale, rotated)
import numpy as np
spec_img = 10 * np.log10(Sxx + 1e-10)
spec_img = np.clip((spec_img - spec_img.min()) / (spec_img.max() - spec_img.min()) * 255, 0, 255).astype(np.uint8)
from PIL import Image
img = Image.fromarray(np.flipud(spec_img))
img.save('D:/test/CTF/7981/spectrogram.png')
print(f"Spectrogram saved: {spec_img.shape}, freq range: {f[0]:.1f}-{f[-1]:.1f}Hz, time: 0-{t_spec[-1]:.1f}s")

# Also try with different parameters focused on 0-2000 Hz range
f2, t2, Sxx2 = signal.spectrogram(samples.astype(np.float32) / 32768.0, rate,
                                    nperseg=1024, noverlap=512, nfft=4096)
# Only keep 0-2000 Hz range
freq_mask = f2 <= 2000
spec_img2 = 10 * np.log10(Sxx2[freq_mask, :] + 1e-10)
spec_img2 = np.clip((spec_img2 - spec_img2.min()) / (spec_img2.max() - spec_img2.min()) * 255, 0, 255).astype(np.uint8)
img2 = Image.fromarray(np.flipud(spec_img2))
img2.save('D:/test/CTF/7981/spectrogram_lowfreq.png')
print(f"Low-freq spectrogram saved: {spec_img2.shape}")

# ============ APPROACH 4: Raw samples as image ============
print("\n=== APPROACH 4: Samples as Image ===")
total = len(samples)
# Try different image dimensions
for w in [256, 512, 640, 1024, 2048, 2400, 2730]:
    h = total // w
    if h < 1:
        continue
    trimmed = samples[:w * h].reshape((h, w))
    # Normalize to 0-255
    img_data = ((trimmed.astype(np.float64) + 32768) / 65536 * 255).clip(0, 255).astype(np.uint8)
    img = Image.fromarray(img_data)
    img.save(f'D:/test/CTF/7981/samples_{w}x{h}.png')
    # Also try as raw bytes
    raw_bytes = samples.astype(np.int16).tobytes()
    raw_pixels = np.frombuffer(raw_bytes, dtype=np.uint8)[:w * h].reshape((h, w))
    img2 = Image.fromarray(raw_pixels)
    img2.save(f'D:/test/CTF/7981/rawbytes_{w}x{h}.png')

print("Saved sample images")

# ============ APPROACH 5: Check for Manchester encoding / different FSK timing ============
print("\n=== APPROACH 5: Timing analysis ===")
# Detect zero crossings to find frequency at each point
zc_steps = []
step = 441  # 10ms
for i in range(0, len(samples) - step, step):
    chunk = samples[i:i+step]
    crossings = np.sum(np.abs(np.diff(np.signbit(chunk))))
    freq_est = crossings * rate / (2 * step)
    zc_steps.append(freq_est)

# Find segments where frequency is close to 1195
threshold = 800
in_1195 = False
segments = []
seg_start = 0
for i, f in enumerate(zc_steps):
    time_sec = i * step / rate
    if f > threshold and not in_1195:
        seg_start = time_sec
        in_1195 = True
    elif f <= threshold and in_1195:
        segments.append((seg_start, time_sec, time_sec - seg_start))
        in_1195 = False
if in_1195:
    segments.append((seg_start, len(zc_steps) * step / rate, len(zc_steps) * step / rate - seg_start))

print(f"1195 Hz segments: {len(segments)}")
for start, end, dur in segments[:30]:
    print(f"  {start:.2f}s - {end:.2f}s ({dur:.3f}s)")

# Check segment duration clustering
durations = [s[2] for s in segments if s[2] < 5]
if durations:
    print(f"Duration stats: min={min(durations):.3f}s, max={max(durations):.3f}s, mean={np.mean(durations):.3f}s")
    from collections import Counter
    rounded = [round(d, 1) for d in durations]
    print(f"Duration clusters: {Counter(rounded).most_common(10)}")
