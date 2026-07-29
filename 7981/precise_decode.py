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

# Zero-crossing approach for frequency detection
def detect_bits_zc(samples, rate, win_samples):
    """Detect bits using zero-crossing frequency estimation"""
    n_windows = len(samples) // win_samples
    bits = np.zeros(n_windows, dtype=np.uint8)
    threshold = 800  # Midpoint between 495 and 1195
    
    for i in range(n_windows):
        chunk = samples[i*win_samples:(i+1)*win_samples]
        crossings = np.sum(np.abs(np.diff(np.signbit(chunk))))
        freq_est = crossings * rate / (2 * win_samples)
        bits[i] = 1 if freq_est > threshold else 0
    
    return bits

# Also use band-pass filter approach
def detect_bits_bpf(samples, rate, win_samples):
    """Use two band-pass filters and compare energy"""
    from scipy.signal import butter, filtfilt
    
    n_windows = len(samples) // win_samples
    bits = np.zeros(n_windows, dtype=np.uint8)
    
    for i in range(n_windows):
        chunk = samples[i*win_samples:(i+1)*win_samples]
        fft = np.abs(np.fft.rfft(chunk))
        freqs = np.fft.rfftfreq(len(chunk), 1/rate)
        
        # Sum power in bands around 495 and 1195
        mask_495 = (freqs >= 450) & (freqs <= 540)
        mask_1195 = (freqs >= 1150) & (freqs <= 1240)
        
        p_495 = np.sum(fft[mask_495])
        p_1195 = np.sum(fft[mask_1195])
        
        bits[i] = 1 if p_1195 > p_495 else 0
    
    return bits

# Try multiple window sizes with better frequency band detection
for win_s in [441, 882, 1102, 1470, 2205]:
    bits = detect_bits_bpf(samples, rate, win_s)
    z = np.sum(bits == 0)
    o = np.sum(bits == 1)
    print(f"Win={win_s} ({win_s/rate*1000:.1f}ms): {len(bits)} bits, 0:{z} 1:{o}")
    
    if win_s == 882:
        print(f"  First 100 bits: {''.join(str(b) for b in bits[:100])}")
        print(f"  Bits 100-200: {''.join(str(b) for b in bits[100:200])}")
        print(f"  Bits 200-300: {''.join(str(b) for b in bits[200:300])}")
        print(f"  Bits around 30: {''.join(str(b) for b in bits[25:35])}")
        print(f"  Bits around 60: {''.join(str(b) for b in bits[57:63])}")
    
    n_bits = len(bits)
    # Test 23x347 image
    if n_bits >= 7981:
        bits_list = bits[:7981].tolist()
        for h, w in [(23, 347), (347, 23)]:
            img_data = np.array(bits_list[:w*h]).reshape((h, w)) * 255
            img = Image.fromarray(img_data.astype(np.uint8))
            img.save(f"D:/test/CTF/7981/fsq_{win_s}_{w}x{h}.png")
            print(f"  Image: {w}x{h} saved")

# Also try to directly look at the timing pattern of 1195 Hz
print("\n=== Precise frequency transition detection ===")
# Use high-resolution frequency detection
step = 220  # 5ms steps
freqs_detected = []
for i in range(0, n - 4410, step):  # Use 0.1s window
    chunk = samples[i:i+4410]
    fft = np.abs(np.fft.rfft(chunk * np.hanning(len(chunk))))
    freqs = np.fft.rfftfreq(len(chunk), 1/rate)
    
    mask_495 = (freqs >= 450) & (freqs <= 540)
    mask_1195 = (freqs >= 1150) & (freqs <= 1240)
    
    p_495 = np.sum(fft[mask_495])
    p_1195 = np.sum(fft[mask_1195])
    
    freqs_detected.append(1 if p_1195 > p_495 * 1.5 else 0)

# Analyze transitions
transitions = []
prev = freqs_detected[0]
for i in range(1, len(freqs_detected)):
    if freqs_detected[i] != prev:
        t = i * step / rate
        t_prev = (i-1) * step / rate
        transitions.append((t_prev, t, prev))
        prev = freqs_detected[i]

print(f"Total transitions: {len(transitions)}")
print("First 30 transitions:")
for i, (start, end, val) in enumerate(transitions[:30]):
    print(f"  #{i}: {start:.3f}s-{end:.3f}s ({end-start:.3f}s) = {val}")

# Check the pattern between pulses
print("\nSpacing between consecutive 1195 Hz pulses:")
pulse_times = []
for start, end, val in transitions:
    if val == 1:
        pulse_times.append((start + end) / 2)

for i in range(1, min(30, len(pulse_times))):
    gap = pulse_times[i] - pulse_times[i-1]
    print(f"  Pulse {i}: gap={gap:.4f}s")
