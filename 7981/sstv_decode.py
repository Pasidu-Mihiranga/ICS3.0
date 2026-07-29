import numpy as np
import struct
import wave

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

# Write a clean WAV
with wave.open('D:/test/CTF/7981/clean.wav', 'w') as wf:
    wf.setnchannels(1)
    wf.setsampwidth(2)
    wf.setframerate(44100)
    wf.writeframes(audio_data)

# Now try SSTV decode
from sstv import SSTV, MODES
print("Modes:", list(MODES.keys()))

with wave.open('D:/test/CTF/7981/clean.wav', 'rb') as wf:
    rate = wf.getframerate()
    nframes = wf.getnframes()
    audio = np.frombuffer(wf.readframes(nframes), dtype=np.int16).astype(np.float32) / 32768.0

print(f"Audio: {len(audio)} samples, {rate} Hz, {len(audio)/rate:.2f}s")

for mode_name in MODES:
    try:
        img = SSTV.decode(audio, rate, mode=mode_name)
        print(f"Mode {mode_name}: SUCCESS - {img.size}")
        if img.size[0] > 0 and img.size[1] > 0:
            img.save(f"D:/test/CTF/7981/sstv_{mode_name}.png")
    except Exception as e:
        print(f"Mode {mode_name}: {type(e).__name__}: {str(e)[:80]}")
