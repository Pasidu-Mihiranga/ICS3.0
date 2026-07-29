import struct
import numpy as np

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
lsb_bytes = bytes(int(lsb_bits[i:i+8], 2) for i in range(0, len(lsb_bits) - 7, 8))

# === Extract LSB with stride ===
print("=== LSB with different strides ===")
for stride in [200, 79, 81, 2, 5, 10]:
    subset = []
    for i in range(0, len(samples), stride):
        subset.append(samples[i] & 1)
    bit_str = ''.join(str(b) for b in subset)
    sub_bytes = bytes(int(bit_str[i:i+8], 2) for i in range(0, len(bit_str) - 7, 8))
    
    # Check for signatures
    for sig, name in [(b'PK\x03\x04', 'ZIP'), (b'\x1f\x8b\x08', 'GZIP')]:
        idx = sub_bytes.find(sig)
        if idx >= 0:
            print(f"  stride={stride}: FOUND {name} at {idx} ({len(sub_bytes)} bytes total)")
    
    # Show first 50 bytes
    text_preview = ''.join(chr(b) if 32<=b<=126 else '.' for b in sub_bytes[:50])
    print(f"  stride={stride}: {len(sub_bytes)} bytes, preview: {text_preview}")

# === Try byte at specific offsets based on hints ===
print("\n=== Bytes at specific offsets ===")
for offset in [0, 200, 7981]:
    chunk = lsb_bytes[offset:offset+100]
    text = ''.join(chr(b) if 32<=b<=126 else '.' for b in chunk)
    print(f"  offset {offset}: {text}")

# === Search ALL bytes for 'flag', 'CTF', 'ICS', 'pass', 'key', 'secret' ===
for word in [b'flag', b'CTF', b'ICS', b'pass', b'key{', b'secr', b'pwd']:
    idx = lsb_bytes.lower().find(word.lower())
    if idx != -1:
        ctx = lsb_bytes[max(0,idx-10):idx+30]
        ctx_text = ''.join(chr(b) if 32<=b<=126 else '.' for b in ctx)
        print(f"  Found '{word.decode()}' at {idx}: ...{ctx_text}...")
    else:
        print(f"  NOT found: '{word.decode()}'")

# === Try decrypting LSB data as a ZIP or encrypted file ===
# The LSB data might be a TrueCrypt/Veracrypt volume, KeePass DB, etc.
for sig, name in [(b'\x76\x68', 'Veracrypt'), (b'\xb1\x27', 'BitLocker'),
                   (b'\x03\xd9', 'KDBX v3'), (b'\x03\xd9\xa2\x9a', 'KDBX v4'),
                   (b'\x9a\xa2\xd9\x03', 'KDBX v4 SWAP'), (b'\x67\xfb', 'KDB')]:
    idx = lsb_bytes.find(sig)
    if idx != -1:
        print(f"  FOUND {name} signature at offset {idx}")

# === Look at A|V kh pattern more carefully ===
print("\n=== 'A|V kh' pattern analysis ===")
pattern = 'A|V kh'
idx = 0
occurrences = []
while True:
    idx = lsb_bytes.find(pattern.encode(), idx)
    if idx == -1:
        break
    ctx20 = lsb_bytes[max(0,idx-5):idx+15]
    ctx20_text = ''.join(chr(b) if 32<=b<=126 else f'\\x{b:02x}' for b in ctx20)
    occurrences.append((idx, ctx20_text))
    print(f"  at offset {idx:7d}: ...{ctx20_text}...")
    idx += 1
    if len(occurrences) >= 15:
        break

# === Look at the spectrogram again for visual data ===
from scipy import signal
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# High-res spectrogram focused on lower frequencies
f, t_spec, Sxx = signal.spectrogram(samples.astype(np.float64), 44100,
                                      nperseg=512, noverlap=256, nfft=2048)

# Only 0-2000 Hz
mask = f <= 2000
f_zoom = f[mask]
S_zoom = Sxx[mask, :]

fig, ax = plt.subplots(figsize=(40, 8))
ax.pcolormesh(t_spec, f_zoom, 10*np.log10(S_zoom + 1e-10), shading='gouraud', cmap='inferno')
ax.set_ylabel('Frequency (Hz)')
ax.set_xlabel('Time (s)')
ax.set_title('Spectrogram (0-2000 Hz)')
fig.savefig('D:/test/CTF/7981/spectrogram_hires.png', dpi=150, bbox_inches='tight')
plt.close()
print("\nHigh-res spectrogram saved")

# Also save as raw pixel data
spec_img = 10 * np.log10(S_zoom + 1e-10)
spec_img = np.clip((spec_img - spec_img.min()) / (spec_img.max() - spec_img.min()) * 255, 0, 255).astype(np.uint8)
from PIL import Image
# Flip and rotate for better viewing
img = Image.fromarray(spec_img)
img = img.resize((spec_img.shape[1]*4, spec_img.shape[0]*4), Image.NEAREST)
img.save('D:/test/CTF/7981/spectrogram_zoom.png')
print("Zoomed spectrogram saved")
