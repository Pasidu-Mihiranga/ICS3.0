#!/usr/bin/env python3
"""Fairchild - full solve. Requires: pillow, numpy

stratofortress.pdf is really a PNG. Seven characters are hidden across seven
containers (trailer, EXIF, LSB, appended ZIP, zTXt, a private quTx chunk, and
one drawn in the image). Each payload carries its own poem line as a join key,
so the rendered image gives the ordering. Assembled they spell FH-227D; the
flag is md5("FH-227D") (a transformation, not a translation).
"""
import base64, hashlib, io, re, struct, sys, zipfile, zlib
import numpy as np
from PIL import Image

PATH = sys.argv[1] if len(sys.argv) > 1 else "fairchild/stratofortress.pdf"
data = open(PATH, "rb").read()

FRAGMENT = re.compile(rb"\*(.)\*\n([0-9a-f]{32})\n([ -~]+)")
found = {}   # poem line -> (char, md5, source)


def record(source, blob):
    for ch, md5, line in FRAGMENT.findall(blob):
        line = line.decode().rstrip("PK")        # strip ZIP magic that can trail
        found[line] = (ch.decode(), md5.decode(), source)


# ---- walk the chunk table by hand -----------------------------------------
chunks, off = [], 8
while off < len(data):
    (ln,) = struct.unpack(">I", data[off:off + 4])
    typ = data[off + 4:off + 8]
    chunks.append((typ.decode("latin1"), data[off + 8:off + 8 + ln]))
    off += 12 + ln
    if typ == b"IEND":
        break
trailing = data[off:]

for typ, body in chunks:
    if typ == "zTXt":                                   # slot 6
        record("zTXt chunk", zlib.decompress(body.split(b"\x00", 1)[1][1:]))
    if typ in ("eXIf", "quTx"):                         # slots 2 and 7
        for m in re.findall(rb"[A-Za-z0-9+/]{40,}={0,2}", body):
            try:
                record(f"{typ} chunk", base64.b64decode(m))
            except Exception:
                pass

# ---- appended ZIP (slot 5) and post-EOCD text (slot 1) ---------------------
for m in re.finditer(rb"PK\x03\x04", trailing):
    z = zipfile.ZipFile(io.BytesIO(trailing[m.start():]))
    for name in z.namelist():
        record(f"appended ZIP ({name})", z.read(name))
record("post-EOCD trailer", trailing)

# ---- LSB stego (slot 4) ----------------------------------------------------
px = np.array(Image.open(PATH).convert("RGB")).reshape(-1, 3).ravel()
record("LSB", np.packbits((px & 1).astype(np.uint8)).tobytes())

# ---- assemble in poem order (slot 3 is drawn in the image) -----------------
POEM = [
    "A name carried by wings, twice marked by disaster",
    "The sky turned from routine into something unrecoverable",
    None,                                                   # the hyphen
    "Metal came to rest where it was never meant to stop",
    "What followed depended entirely on where it fell",
    "Some tellings end in silence, others in survival",
    "The name Fairchild outlived every version of the story",
]

name = ""
for line in POEM:
    if line is None:
        name += "-"
        continue
    ch, md5, _ = found[line]
    assert hashlib.md5(ch.encode()).hexdigest() == md5 or md5 == hashlib.md5(b"").hexdigest()
    name += ch

print("assembled name :", name)                    # FH-227D
digest = hashlib.md5(name.encode()).hexdigest()    # the transformation
print("flag           : ICS{%s}" % digest)
