# The Contaminated Container — Writeup

**Category:** DevOps / Container Forensics  
**Difficulty:** Medium  
**Flag:** `ICS{d3l3t3d_fr0m_v13w_n0t_fr0m_h15t0ry}`

---

## Challenge

Frostline Payroll's Ledger API image passed its final runtime scan. The builder admitted recovery material was copied during compilation but insisted it had been deleted before publication. Hours later, an unauthorized maintenance license was accepted. Incident responders preserved the published image.

Determine what the image still remembers and recover the license message.

## Solution

### 1. Extract the Docker image layers

The attachment `deleted-container-image.tar` is a `docker save` export. Extracting the tar reveals the standard OCI layout:

```
manifest.json
repositories
<layer_id>/layer.tar  (×5 layers)
```

Five rootfs layers in order:

| Order | Layer ID (short) | Description |
|-------|-----------------|-------------|
| 1 | a6b5835b | Base minirootfs |
| 2 | 8a8fee6e | Dependencies (python3, ca-certs) |
| 3 | 5c959ef4 | Recovery material copied from build context |
| 4 | c836fd83 | Cleanup — `rm -f fragment-a.txt` |
| 5 | 9865adf9 | Application release (`/app/`) |

### 2. Layer 3 — the deleted file that still exists

Layer 3 contains `/opt/build/.recovery/fragment-a.txt`:

```
1m4g3_l4y3r5_
```

Layer 4 contains the whiteout file `/opt/build/.recovery/.wh.fragment-a.txt` (empty), which signals the file was "deleted" in the overlay. But when each layer is extracted individually, the original file is still there — Docker layers are immutable, deletion is an overlay mask.

### 3. Docker history — the cleared environment variable

The image config JSON (`aeb07311...json`) contains the full build history:

```json
{
  "comment": "recovery material copied from build context",
  "created_by": "/bin/sh -c #(nop) COPY dir:8d2c491f in /opt/build/"
},
{
  "created_by": "/bin/sh -c #(nop)  ENV RECOVERY_FRAGMENT_B=r3m3mb3r",
  "empty_layer": true
},
{
  "created_by": "/bin/sh -c rm -f /opt/build/.recovery/fragment-a.txt"
},
{
  "created_by": "/bin/sh -c #(nop)  ENV RECOVERY_FRAGMENT_B=",
  "empty_layer": true
}
```

`RECOVERY_FRAGMENT_B` was set to `r3m3mb3r` in layer 4 and cleared in layer 6. Both are empty layers — only recorded in the history, never present in an actual rootfs. But the Docker config preserves every command.

### 4. License decryption — `maintenance-loader.pyc`

The top layer contains:

```
/app/config.json         — points to /app/license.dat
/app/license.dat         — encrypted license payload
/app/maintenance-loader.pyc — compiled Python loader
/app/maintenance.status  — record format = DCLIC-V1
/app/server.sh           — entrypoint
```

Decompiling `maintenance-loader.pyc` (Python 3.12) reveals:

```python
HEADER = b'DCLIC-V1\x00'

def open_record(path, left, right):
    blob = path.read_bytes()
    if not blob.startswith(HEADER):
        raise ValueError('unsupported record')
    start = len(HEADER)               # 9
    counter = blob[start:start + 16]  # 16-byte CTR nonce
    payload = blob[start + 16:]       # encrypted body
    secret = hashlib.sha256((left + right).encode('utf-8')).digest()
    cipher = AES.new(secret, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(counter, 'big')))
    return json.loads(cipher.decrypt(payload).decode('utf-8'))
```

Usage: `python maintenance-loader.pyc <RECORD> <LEFT> <RIGHT>`

The two recovery fragments combine into the AES-CTR key:

- **LEFT** = `1m4g3_l4y3r5_` (from deleted `fragment-a.txt`)
- **RIGHT** = `r3m3mb3r` (from `ENV RECOVERY_FRAGMENT_B` in Docker history)
- **Key** = `SHA256("1m4g3_l4y3r5_r3m3mb3r")`

Running the decrypt script against `license.dat` yields:

```json
{
  "flag": "ICS{d3l3t3d_fr0m_v13w_n0t_fr0m_h15t0ry}",
  "incident": "FROSTLINE-BUILD-7241",
  "lesson": "Deleting a file in a later layer does not erase the earlier layer."
}
```

## Key Takeaways

1. **Docker layer whiteouts don't erase data.** A `.wh.` file only hides the entry in the UnionFS overlay. The original layer still carries the file.
2. **Empty layers persist in history.** `ENV` commands create empty layers whose values remain visible in the image config even after being overwritten.
3. **Container forensics requires examining all layers independently**, not just the final merged filesystem.

## Files

- `solve.py` — Decryption script
