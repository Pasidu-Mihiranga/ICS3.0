import struct, numpy as np

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

rate = 44100
samples = np.frombuffer(audio, dtype=np.int16)
total = len(samples)

# ===== Extract at 200 samples/second =====
# 44100/200 = 220.5 samples per "bit"
# Alternating between 220 and 221 sample steps
step = 44100 / 200  # 220.5
accum = 0.0
indices = []
while accum < total:
    indices.append(int(accum))
    accum += step
indices = np.array(indices[:total])

sub_samples = samples[indices]
sub_lsb = (sub_samples & 1).astype(np.uint8)
sub_padded = np.pad(sub_lsb, (0, 8 - len(sub_lsb) % 8) if len(sub_lsb) % 8 else (0, 0))
sub_bytes = np.packbits(sub_padded).tobytes()[:len(sub_lsb)//8]

print(f"200Hz LSB: {len(sub_samples)} samples, {len(sub_bytes)} bytes")
print(f"First 100 bytes hex: {sub_bytes[:100].hex()}")
text = ''.join(chr(b) if 32<=b<=126 else '.' for b in sub_bytes[:200])
print(f"Text: {text}")

# Check for archive signatures
for sig, name in [(b'PK\x03\x04', 'ZIP'), (b'\x1f\x8b\x08', 'GZIP'),
                   (b'iCS{', 'FLAG'), (b'ICS{', 'FLAG')]:
    idx = sub_bytes.find(sig)
    if idx != -1:
        print(f"FOUND {name} at offset {idx}!")
        if 'FLAG' in name:
            end = sub_bytes.find(b'}', idx)
            if end != -1:
                print(f"  {sub_bytes[idx:end+1].decode()}")
    else:
        print(f"  No {name}")

# === Also try: NOT LSB, but the FULL sample values at 200Hz as bytes ===
print("\n=== Full 16-bit values at 200Hz ===")
sub_raw = sub_samples.tobytes()
for sig, name in [(b'PK\x03\x04', 'ZIP')]:
    idx = sub_raw.find(sig)
    if idx != -1:
        print(f"FOUND {name} at {idx}!")
    else:
        print(f"  No {name} in full values")

# === Try different bit positions at 200Hz ===
print("\n=== Bit positions at 200Hz LSB ===")
for bit_pos in range(16):
    sub_bits = ((sub_samples >> bit_pos) & 1).astype(np.uint8)
    sub_pad = np.pad(sub_bits, (0, 8 - len(sub_bits) % 8) if len(sub_bits) % 8 else (0, 0))
    sub_b = np.packbits(sub_pad).tobytes()[:len(sub_bits)//8]
    for sig, name in [(b'PK\x03\x04', 'ZIP'), (b'iCS{', 'FLAG'), (b'ICS{', 'FLAG')]:
        if sig in sub_b[:2000]:
            print(f"  Bit {bit_pos}: FOUND {name}!")
            break
    else:
        if bit_pos < 4:
            text_bp = ''.join(chr(b) if 32<=b<=126 else '.' for b in sub_b[:100])
            print(f"  Bit {bit_pos}: {text_bp[:60]}")

# === Also try with stride 200 starting at sample 0 ===
print("\n=== Stride 200 from sample 0 ===")
stride_samples = samples[::200]
stride_lsb = (stride_samples & 1).astype(np.uint8)
stride_pad = np.pad(stride_lsb, (0, 8 - len(stride_lsb) % 8) if len(stride_lsb) % 8 else (0, 0))
stride_bytes = np.packbits(stride_pad).tobytes()[:len(stride_lsb)//8]
print(f"Stride 200: {len(stride_samples)} samples, {len(stride_bytes)} bytes")
for sig, name in [(b'PK\x03\x04', 'ZIP'), (b'iCS{', 'FLAG'), (b'ICS{', 'FLAG')]:
    idx = stride_bytes.find(sig)
    if idx != -1:
        print(f"  FOUND {name} at {idx}!")
    else:
        print(f"  No {name}")
stride_text = ''.join(chr(b) if 32<=b<=126 else '.' for b in stride_bytes[:200])
print(f"  Text: {stride_text[:120]}")

# === The 700 Hz band was active - try extracting data from frequency domain ===
print("\n=== 700 Hz signal extraction ===")
from scipy import signal

# Band-pass filter for 700 Hz and extract the envelope (amplitude)
b, a = signal.butter(4, [680/22050, 720/22050], btype='band')
filtered = signal.filtfilt(b, a, samples.astype(np.float64))
envelope = np.abs(filtered)
# Threshold to get on/off
threshold = np.mean(envelope) * 1.5
digital_signal = (envelope > threshold).astype(np.uint8)

# Find transitions
transitions = np.diff(digital_signal)
rise_times = np.where(transitions == 1)[0]
fall_times = np.where(transitions == -1)[0]

print(f"700Hz: {len(rise_times)} rises, {len(fall_times)} falls")

# Try to decode as bits based on timing
if len(rise_times) > 0:
    # Duration of each "on" pulse
    pulse_widths = []
    for r, f in zip(rise_times[:len(fall_times)], fall_times[:len(rise_times)]):
        pulse_widths.append((f - r) / rate)
    
    from collections import Counter
    width_counts = Counter([round(w, 3) for w in pulse_widths[:100]])
    print(f"  Pulse width clusters: {width_counts.most_common(10)}")
    
    # Gap widths (off durations)
    gap_widths = []
    for i in range(len(fall_times) - 1):
        if i + 1 < len(rise_times):
            gap_widths.append((rise_times[i+1] - fall_times[i]) / rate)
    gap_counts = Counter([round(g, 3) for g in gap_widths[:100]])
    print(f"  Gap width clusters: {gap_counts.most_common(10)}")
