# The Candidate Who Never Whispered — Write-up

## Challenge summary

The archive contains:

- `campaign-poster.png`
- `show_transcript.txt`
- `interview_notes.txt`
- `private_broadcast.enc`

The objective is to recover the extraction instructions hidden throughout the
archive and use them to decrypt Crown's private message.

## 1. Recover the hidden instructions

### The campaign poster

The illuminated paragraph on `campaign-poster.png` contains nine lines.
Reading the first letter of each line gives:

```text
F I B O N A C C I
```

The first instruction is therefore:

```text
FIBONACCI
```

This matches the warning that the message was hidden inside the way the
"spotlight" was constructed.

### The interview notes

The interview contains the following clues:

```text
It's just natural growth.
```

Natural growth is a common reference to the Fibonacci sequence.

The second response says:

```text
A woven boundary. Just like a ZigZag. Exactly three times high.
```

A message written in a repeating zigzag is a Rail Fence cipher. "Exactly
three times high" specifies three rails.

The resulting instruction is:

```text
RAIL FENCE, 3 RAILS
```

### The show transcript

The transcript tells us to choose the odd-numbered doors. Remove the hyphens
from the episode ID:

```text
BRAASI-EL-634
→ BRAASIEL634
```

Separating its characters by 1-based odd and even positions gives:

```text
Odd positions:  BASE64
Even positions: RAIL3
```

This confirms that the broadcast uses Base64-looking cover data and that the
extracted text must be processed as a three-rail Rail Fence cipher.

## 2. Extract the concealed ciphertext

Treat the characters in `private_broadcast.enc` as 1-based. Read the
characters found at Fibonacci-numbered positions:

```text
1, 2, 3, 5, 8, 13, 21, 34, 55, 89, ...
```

The extracted characters are:

```text
F{305WLG47N1N1_03}A77_PR
```

This resembles a flag, but its characters are still transposed.

## 3. Decrypt the Rail Fence ciphertext

Decrypt the extracted string using a three-rail Rail Fence cipher:

```text
F{305WLG47N1N1_03}A77_PR
→ FLAG{4773N710N_15_P0W3R}
```

The flag body is leetspeak for:

```text
ATTENTION IS POWER
```

## Reproducible solver

Run the following script from the challenge directory:

```python
from pathlib import Path


def fibonacci_positions(limit):
    """Return zero-based indexes for 1-based Fibonacci positions."""
    positions = []
    first, second = 1, 2

    while first <= limit:
        positions.append(first - 1)
        first, second = second, first + second

    return positions


def rail_fence_decrypt(ciphertext, rails):
    cycle = list(range(rails)) + list(range(rails - 2, 0, -1))
    pattern = [cycle[index % len(cycle)] for index in range(len(ciphertext))]

    row_lengths = [pattern.count(row) for row in range(rails)]

    rows = []
    offset = 0

    for length in row_lengths:
        rows.append(list(ciphertext[offset : offset + length]))
        offset += length

    return "".join(rows[row].pop(0) for row in pattern)


broadcast = Path("private_broadcast.enc").read_text().strip()

positions = fibonacci_positions(len(broadcast))
extracted = "".join(broadcast[index] for index in positions)
plaintext = rail_fence_decrypt(extracted, 3)

print(f"Extracted: {extracted}")
print(f"Decrypted: {plaintext}")
```

Output:

```text
Extracted: F{305WLG47N1N1_03}A77_PR
Decrypted: FLAG{4773N710N_15_P0W3R}
```

The event uses the case-sensitive mixed-case prefix `iCS`, so the generic
`FLAG` prefix must be replaced with `iCS`.

## Flag

```text
iCS{4773N710N_15_P0W3R}
```
