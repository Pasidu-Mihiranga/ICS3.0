# The Seduction — Cryptography (300)

## Flag

`ICS{v3lv3t_st4t1c_h0ps_3142_7c9e}`

## Analysis

`the_seduction.wav` is a 42-second, 44.1 kHz, 16-bit stereo WAV.  Its
`LIST/INFO` metadata contains an AES payload:

```text
METHOD=AES-256-CTR
KDF=SHA-256
IV=7b94076bad31296433ef473eb3da7ccf
DATA=800e6cd3...dc53afd4eef
```

The audio clue points to frequency hopping (an allusion to Hedy Lamarr).
The useful signal is not the normal stereo mix: subtracting the right channel
from the left isolates a clean hopping signal from 12.0 to 26.4 seconds.

It changes frequency every 0.12 seconds.  The eight frequencies form four
binary FSK pairs:

| Pair | Bit 0 | Bit 1 |
|---:|---:|---:|
| 0 | 880 Hz | 1080 Hz |
| 1 | 1400 Hz | 1600 Hz |
| 2 | 1880 Hz | 2080 Hz |
| 3 | 2400 Hz | 2600 Hz |

The active pair is the hop carrier; whether the lower or upper frequency of
that pair is used is the data bit.  Reading the 120 bits MSB-first gives the
two-byte preamble `55 aa`, followed by:

```text
VELVET STATIC
```

The metadata says to SHA-256 this phrase for the AES-256 key.  Decrypting the
CTR ciphertext yields:

```text
The audience saw a face.
The enemy heard only noise.
ICS{v3lv3t_st4t1c_h0ps_3142_7c9e}
```

## Solver

```python
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
```
