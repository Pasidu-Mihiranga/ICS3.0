#!/usr/bin/env python3
"""The Impossible Meeting - solver.

Usage: python impossible_meeting_solve.py [path/to/impossible-meeting.ics]
"""
import base64
import datetime
import re
import sys
import zlib
from zoneinfo import ZoneInfo

PATH = sys.argv[1] if len(sys.argv) > 1 else "extracted/the-impossible-meeting/impossible-meeting.ics"

# --- 1. unfold the ICS (RFC 5545: a leading space continues the previous line)
raw = open(PATH, encoding="utf-8").read()
lines = raw.replace("\r\n", "\n").replace("\n ", "").split("\n")

# --- 2. pull the overridden occurrences (the ones with a RECURRENCE-ID)
#        the master VEVENT's RRULE gives 8 days, EXDATE removes 2026-03-28 -> 7 left,
#        and each of those 7 has an override whose DTSTART is when it *actually* ran.
UTC = datetime.timezone.utc
starts = []
for i, line in enumerate(lines):
    m = re.match(r"DTSTART(?:;TZID=([^:]+))?:(\d{8}T\d{6})(Z?)$", line)
    if not m:
        continue
    # only the overrides: their VEVENT block carries a RECURRENCE-ID
    block = "\n".join(lines[max(0, i - 6):i + 6])
    if "RECURRENCE-ID" not in block:
        continue
    tzid, stamp, zulu = m.groups()
    tz = UTC if (zulu or not tzid) else ZoneInfo(tzid)
    starts.append(datetime.datetime.strptime(stamp, "%Y%m%dT%H%M%S").replace(tzinfo=tz))

assert len(starts) == 7, f"expected 7 accepted meetings, got {len(starts)}"

# --- 3. "queue on the world's common clock" -> sort by UTC instant
#        "epoch seconds turn on a 256-mark dial; one mark remains from each" -> % 256
epochs = sorted(int(d.timestamp()) for d in starts)
key = bytes(e % 256 for e in epochs)

for e in epochs:
    print(f"{datetime.datetime.fromtimestamp(e, UTC):%Y-%m-%d %H:%M:%S}Z  "
          f"epoch={e}  %256={e % 256:3d} {chr(e % 256)!r}")
print(f"\nkey = {key.decode()!r}\n")

# --- 4. decode the attachment
attach = next(l for l in lines if l.startswith("ATTACH"))
blob = base64.b64decode(attach.rsplit(":", 1)[1])
assert blob[:6] == b"IMTG1\x00", blob[:6]

# "after the IMTG1 seal, seven marks circle over packed minutes; matching bits cancel"
#   seal   = 6-byte header    circle = repeating XOR
#   packed = raw DEFLATE      cancel = XOR
body = blob[6:]
plain = bytes(c ^ key[i % len(key)] for i, c in enumerate(body))

# decompressobj, not zlib.decompress: the stream has no final-block terminator
flag = zlib.decompressobj(-15).decompress(plain)
print(flag.decode().strip())
