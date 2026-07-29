import struct, numpy as np
from scipy import signal
from PIL import Image

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
samples = np.frombuffer(audio, dtype=np.int16).astype(np.float64)
total = len(samples)
duration = total / rate

# ===== FSK at different bitrates with Arecibo-like image output =====
print("=== Arecibo-style FSK Image Decoding ===")
# 7981 bits at 23x347
for bps, win_samples, note in [(50, 882, '50bps-7981bits'),
                                 (200, 220, '200bps-31924bits'),
                                 (100, 441, '100bps-15962bits'),
                                 (25, 1764, '25bps-3990bits')]:
    total_bits = int(duration * bps)
    print(f"\n{note}: {total_bits} bits expected, window={win_samples}")
    
    bits = np.zeros(min(total_bits, len(samples) // win_samples), dtype=np.uint8)
    
    for i in range(len(bits)):
        chunk = samples[i*win_samples:(i+1)*win_samples]
        if len(chunk) < win_samples:
            break
        fft = np.abs(np.fft.rfft(chunk * np.hanning(len(chunk))))
        freqs = np.fft.rfftfreq(len(chunk), 1/rate)
        
        # Compare energy in bands around 495 and 1195 Hz
        mask_495 = (freqs >= 450) & (freqs <= 540)
        mask_1195 = (freqs >= 1150) & (freqs <= 1240)
        p_495 = np.sum(fft[mask_495])
        p_1195 = np.sum(fft[mask_1195])
        bits[i] = 1 if p_1195 > p_495 else 0
    
    n = len(bits)
    z = np.sum(bits == 0)
    o = np.sum(bits == 1)
    print(f"  Actual bits: {n}, 0:{z} 1:{o} ({o/n*100:.1f}% ones)")
    
    # Try known Arecibo factor: 23x347=7981
    if n >= 7981 and bps == 50:
        for h, w in [(23, 347), (347, 23)]:
            sub = bits[:h*w]
            if len(sub) == h * w:
                img = Image.fromarray((sub.reshape((h, w)) * 255).astype(np.uint8))
                img = img.resize((w*3, h*3), Image.NEAREST)
                img.save(f'D:/test/CTF/7981/arecibo_ext_{h}x{w}_50bps.png')
                print(f"  Saved {h}x{w} image (50bps)")
    
    # 4x7981 = 31924 = at 200 bps
    if n >= 31924 and bps == 200:
        for h, w in [(46, 694), (92, 347), (23, 1388), (694, 46), (347, 92)]:
            if h * w <= n:
                sub = bits[:h*w]
                if len(sub) == h * w:
                    img = Image.fromarray((sub.reshape((h, w)) * 255).astype(np.uint8))
                    img = img.resize((max(w//10, 1), max(h//10, 1)), Image.NEAREST)
                    img.save(f'D:/test/CTF/7981/arecibo_ext_{h}x{w}_200bps.png')
                    print(f"  Saved {h}x{w} image (200bps)")

# ===== Amplitude-based decoding of 1195 Hz component =====
print("\n=== Amplitude-based 1195 Hz decoding ===")
# Use a narrow band-pass filter to isolate 1195 Hz
# Then measure its amplitude over time
b, a = signal.butter(6, [1180/22050, 1210/22050], btype='band')
filtered_1195 = signal.filtfilt(b, a, samples)

# Compute envelope (Hilbert transform / absolute value)
from scipy.signal import hilbert
analytic_signal = hilbert(filtered_1195)
amplitude_envelope = np.abs(analytic_signal)

# Decimate to various sample rates
for decimate in [220, 441, 882, 2205]:
    dec_samples = amplitude_envelope[::decimate]
    # Threshold
    med = np.median(dec_samples)
    bits_amp = (dec_samples > med * 2).astype(np.uint8)
    n_bits = len(bits_amp)
    z_count = np.sum(bits_amp == 0)
    o_count = np.sum(bits_amp == 1)
    print(f"  Decimate {decimate}: {n_bits} values, above 2x median: {o_count}")
    
    # Try to form Arecibo image
    for h, w in [(23, 347), (347, 23)]:
        if h * w <= n_bits:
            sub = bits_amp[:h*w]
            img = Image.fromarray((sub.reshape((h, w)) * 255).astype(np.uint8))
            img = img.resize((w*3, h*3), Image.NEAREST)
            img.save(f'D:/test/CTF/7981/amp1195_{h}x{w}_dec{decimate}.png')

# ===== BPSK/QPSK attempt: Phase-based decoding =====
print("\n=== Phase-based decoding ===")
# Look at the phase of the 495 Hz component
b_495, a_495 = signal.butter(4, [480/22050, 510/22050], btype='band')
filtered_495 = signal.filtfilt(b_495, a_495, samples)
analytic_495 = hilbert(filtered_495)
phase_495 = np.angle(analytic_495)
phase_diff = np.diff(np.unwrap(phase_495))

# Check if phase changes encode bits
for dec in [220, 441]:
    pd_subsampled = phase_diff[::dec]
    bits_phase = (pd_subsampled > 0).astype(np.uint8)
    print(f"  Phase diff dec {dec}: {np.sum(bits_phase)}/{len(bits_phase)} positive changes")

# ===== Try sound-of-text approach: DTMF decoding =====
# Maybe the tones encode DTMF digits (like phone keypad)
# Common DTMF: 697, 770, 852, 941 Hz (low) and 1209, 1336, 1477, 1633 Hz (high)
# 1195 is close to 1209. 495 is close to nothing in DTMF.
# So probably not DTMF

# ===== Final check: what if the passphrase is a brainfuck/encoded text? =====
print("\n=== Encoded text search in LSB block ===")
lsb_bits = (samples & 1).astype(np.uint8)
padded = np.pad(lsb_bits, (0, 8 - len(lsb_bits) % 8) if len(lsb_bits) % 8 else (0, 0))
lsb_bytes = np.packbits(padded).tobytes()[:len(lsb_bits)//8]
block = lsb_bytes[:441]

# Check if block is base32
import base64
try:
    b32_decoded = base64.b32decode(block)
    print(f"  Base32 decode: {len(b32_decoded)} bytes -> {b32_decoded[:50]}")
except:
    pass

# Check if block is base58 (like Bitcoin)
# Base58 alphabet
b58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
try:
    import base58
    b58_decoded = base58.b58decode(block)
    print(f"  Base58: {b58_decoded[:50]}")
except:
    pass

# Try ROT13/base64url
# Check if any substring is a flag
for start in range(0, 400):
    for end in range(start + 10, min(start + 100, 441)):
        candidate = block[start:end]
        try:
            text = candidate.decode('ascii')
            if text.startswith('ICS{') or text.startswith('iCS{') or text.startswith('flag{'):
                print(f"  FLAG at {start}:{end}: {text}")
        except:
            pass
