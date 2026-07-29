# The Leader — Write-up

## Overview

The supplied `the_leader_release` file is a stripped, statically linked 64-bit ELF binary.  It asks for four archive fields, but the individual checks are intentionally corrupted and the resulting values are used to derive the flag decryption key.

The useful strings and the main verifier routine are located around virtual address `0x10029f0`.

## Field checks

### ALPHA

The first input is hashed with a DJB2-style recurrence, seeded with `0x1505`:

```text
h = h * 33 + byte
```

The expected final value is `0x7c78cdd3`.  Hashing `1337` gives that value.

### BRAVO

The second input must be exactly ten bytes long.  Its bytes are compared case-insensitively against individual constants, yielding:

```text
c0rrupt10n
```

### CHARLIE

The third check is a compact stack virtual machine.  Its bytecode performs:

```text
((initial_value * 3) - 15) XOR 26
```

and compares the result with `0x172b`.

### DELTA

The fourth check transforms the first two input bytes through several byte arithmetic and XOR operations, then requires the final 16-bit value to be `0xbbb7`.

These conditions are deliberately inconsistent with ordinary printable input when combined: the challenge’s story about corrupted records is literal.  Rather than trying to satisfy the terminal remotely, the flag can be recovered from the final decryption routine.

## Recovering the flag

Once the earlier check results are represented by their success-path constants, the routine constructs this 32-bit key:

```text
0xd34d2bb7
```

It XORs the key into the seed `0x6a09e667f3bcc909` and uses a vectorized SplitMix64-like generator to decrypt 24 bytes.  A scalar version of the same generator derives the six-byte suffix.

The decrypted pieces are:

```text
ICS{1984_c0rrupt10n_1776
_1337}
```

## Flag

```text
ICS{1984_c0rrupt10n_1776_1337}
```
