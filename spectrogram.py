import struct
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

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

# Convert to numpy array
samples = []
for i in range(0, len(audio_raw), 2):
    samples.append(struct.unpack_from('<h', audio_raw, i)[0])
samples = np.array(samples, dtype=np.float32)
sample_rate = 22050

print(f"Samples: {len(samples)}, rate: {sample_rate}")

# Generate spectrogram
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 8))

# Waveform
time_axis = np.arange(len(samples)) / sample_rate
ax1.plot(time_axis, samples, linewidth=0.3)
ax1.set_xlabel('Time (s)')
ax1.set_ylabel('Amplitude')
ax1.set_title('Voice Note Waveform')

# Spectrogram
ax2.specgram(samples, Fs=sample_rate, NFFT=512, noverlap=256, cmap='inferno')
ax2.set_xlabel('Time (s)')
ax2.set_ylabel('Frequency (Hz)')
ax2.set_title('Voice Note Spectrogram')
ax2.set_ylim(0, 8000)

plt.tight_layout()
plt.savefig('C:/Users/Milindu/AppData/Local/Temp/kilo/spectrogram.png', dpi=150)
print("Spectrogram saved")

# Also generate high-res spectrogram for text detection
fig2, ax = plt.subplots(1, 1, figsize=(20, 8))
ax.specgram(samples, Fs=sample_rate, NFFT=256, noverlap=128, cmap='gray')
ax.set_ylim(0, 4000)
ax.set_title('Voice Note High-Res Spectrogram')
plt.tight_layout()
plt.savefig('C:/Users/Milindu/AppData/Local/Temp/kilo/spectrogram_hires.png', dpi=200)
print("High-res spectrogram saved")
