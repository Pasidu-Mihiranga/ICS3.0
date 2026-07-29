#!/usr/bin/env python3
"""
The Seduction - solver.

The useful signal is the stereo side channel (L - R): a frequency-hopping FSK
burst between 12.0 s and 26.4 s. Eight tones form four binary pairs; the lower/
upper tone of the active pair is the data bit. 120 bits MSB-first spell
"\x55\xaaVELVET STATIC"; SHA-256 of "VELVET STATIC" is the AES-256-CTR key that
unlocks the LIST/INFO payload.
"""
import hashlib
import re
import wave
from pathlib import Path

import numpy as np
from Crypto.Cipher import AES

path = Path("the_seduction.wav")
blob = path.read_bytes()
match = re.search(rb"IV=([0-9a-f]+);DATA=([0-9a-f]+)", blob)
iv = bytes.fromhex(match.group(1).decode())
ciphertext = bytes.fromhex(match.group(2).decode())

with wave.open(str(path), "rb") as wav:
    rate = wav.getframerate()
    samples = np.frombuffer(wav.readframes(wav.getnframes()), "<i2")
samples = samples.reshape(-1, 2)

# Remove the common stereo audio and retain the hidden side channel.
side = (samples[:, 0].astype(float) - samples[:, 1].astype(float)) / 2
frequencies = np.array([880, 1080, 1400, 1600, 1880, 2080, 2400, 2600])

symbols = []
for index in range(120):
    # The hopping section is [12.0, 26.4), with 0.12 seconds per symbol.
    center = int((12.0 + (index + 0.5) * 0.12) * rate)
    positions = np.arange(center - 1800, center + 1800)
    window = side[positions]
    strengths = [
        abs(np.dot(window, np.exp(-2j * np.pi * frequency * positions / rate)))
        for frequency in frequencies
    ]
    symbols.append(int(np.argmax(strengths)))

# Adjacent frequencies in each FSK pair represent 0 and 1.
bits = [symbol & 1 for symbol in symbols]
hidden = np.packbits(bits).tobytes()
assert hidden == b"\x55\xaaVELVET STATIC"

key = hashlib.sha256(hidden[2:]).digest()
plaintext = AES.new(
    key,
    AES.MODE_CTR,
    nonce=b"",
    initial_value=int.from_bytes(iv, "big"),
).decrypt(ciphertext)

print(plaintext.decode())
