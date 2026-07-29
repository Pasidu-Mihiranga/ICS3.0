# BOS-400 Telegraph Archive — Write-up

## Challenge summary

The challenge provides two files:

- `challenge.txt`, containing a BOS-400 byte stream and a description of the
  old encoding system.
- `bos_code_card.png`, containing the teller's eight-character visual
  verification key.

The goal is to reverse the recorder and authentication transformations, map
the resulting seven-bit addresses through the supplied codebook, and remove
the terminal's synchronization chatter.

## 1. Recover the authentication material

The code card shows these eight glyphs, preserving their case:

```text
M7KPX9ZL
```

The archive notes say that the 1987 verification fragment `C0D3` came
immediately after the card glyphs. Therefore, the complete authentication
material is:

```text
M7KPX9ZLC0D3
```

The "256-bit member of the seal standardized in FIPS PUB 180-4" is SHA-256.
Hashing the authentication material as ASCII/UTF-8 gives:

```text
SHA256("M7KPX9ZLC0D3")
  = 055f85cf9426a612753caa952d0ba986
    18b72abbb82a3f2f4cb20250a9836bf5
```

Only the leftmost sixteen octets are retained:

```text
05 5f 85 cf 94 26 a6 12 75 3c aa 95 2d 0b a9 86
```

This 16-byte value is repeated to match the length of the message.

## 2. Determine the reversal order

The ledger describes the original forward process:

1. Represent every character as its zero-based address in the codebook.
2. XOR the address bytes with the repeated 16-byte hash prefix.
3. Swap the high and low nibbles of every resulting byte.
4. Store those swapped bytes in the archive.

The note that an output bit is raised only when the corresponding message and
fingerprint bits disagree describes XOR.

To decode the archive, perform the inverse operations in reverse order:

1. Swap the nibbles of every recorded byte. A nibble swap is its own inverse.
2. XOR with the repeated hash prefix. XOR is also its own inverse.
3. Interpret each recovered byte as a codebook address.

For a byte `b`, the nibble swap is:

```text
(b >> 4) | ((b & 0x0f) << 4)
```

## 3. Undo the recorder transformation

The recorded bytes are:

```text
2537 9B4C 0B61 8A34 D702 68BA C2F3 BBEB 13B6 5CCC
3A42 29E1 9790 8B78 81F3 4A1B 6006
```

After swapping the nibbles:

```text
52 73 b9 c4 b0 16 a8 43 7d 20 86 ab 2c 3f bb be
31 6b c5 cc a3 24 92 1e 79 09 b8 87 18 3f a4 b1
06 60
```

XORing these bytes with the repeated 16-byte hash prefix recovers the
codebook addresses:

```text
57 2c 3c 0b 24 30 0e 51 08 1c 2c 3e 01 34 12 38
34 34 40 03 37 02 34 0c 0c 35 12 12 35 34 0d 37
03 3f
```

## 4. Decode the codebook addresses

The supplied codebook is indexed from `0x00`:

```text
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_!@#$%^&*()-=+[]|;:',.<>?/`~<SP>
```

Mapping the recovered addresses through this codebook yields:

```text
>S8lKWo;iCS{b0s400_d3c0mm1ss10n3d}
```

The ledger says the terminal inserted exactly eight codebook characters of
synchronization chatter before each payload. The first eight characters are:

```text
>S8lKWo;
```

Removing them leaves the original payload.

## Reproducible solver

```python
import hashlib

recorded_hex = """
2537 9B4C 0B61 8A34 D702 68BA C2F3 BBEB 13B6 5CCC
3A42 29E1 9790 8B78 81F3 4A1B 6006
"""

codebook = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "{}_!@#$%^&*()-=+[]|;:',.<>?/`~ "
)

card_key = "M7KPX9ZL"
auth_material = (card_key + "C0D3").encode()

# Retain the first 16 bytes of SHA-256.
fingerprint = hashlib.sha256(auth_material).digest()[:16]
recorded = bytes.fromhex(recorded_hex)

# Undo the archive recorder's high/low nibble exchange.
before_recorder = bytes(
    (byte >> 4) | ((byte & 0x0F) << 4)
    for byte in recorded
)

# Undo the authentication XOR gate.
addresses = bytes(
    byte ^ fingerprint[index % len(fingerprint)]
    for index, byte in enumerate(before_recorder)
)

decoded = "".join(codebook[address] for address in addresses)
payload = decoded[8:]

print(f"Fingerprint: {fingerprint.hex()}")
print(f"Decoded:     {decoded}")
print(f"Payload:     {payload}")
```

Output:

```text
Fingerprint: 055f85cf9426a612753caa952d0ba986
Decoded:     >S8lKWo;iCS{b0s400_d3c0mm1ss10n3d}
Payload:     iCS{b0s400_d3c0mm1ss10n3d}
```

## Flag

```text
iCS{b0s400_d3c0mm1ss10n3d}
```
