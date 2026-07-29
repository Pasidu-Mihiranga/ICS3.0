import struct
import numpy as np
import re

with open('D:/test/CTF/7981/7981/0.wav', 'rb') as f:
    raw = f.read()

pos = 12
while pos < len(raw) - 8:
    chunk_id = raw[pos:pos+4]
    chunk_size = struct.unpack_from('<I', raw, pos+4)[0]
    if chunk_id == b'data':
        audio = raw[pos+8:pos+8+chunk_size]
        break
    pos += 8 + chunk_size

samples = np.frombuffer(audio, dtype=np.int16)

lsb_bits = ''.join(str(s & 1) for s in samples)
lsb_bytes = bytes(int(lsb_bits[i:i+8], 2) for i in range(0, len(lsb_bits) - 7, 8))
print(f"LSB data: {len(lsb_bytes)} bytes")

# Look for archive signatures
for sig, name, ext in [(b'PK\x03\x04', 'ZIP', '.zip'), (b'\x1f\x8b\x08', 'GZIP', '.gz'),
                          (b'Rar!\x1a\x07', 'RAR', '.rar'), (b'7z\xbc\xaf\x27\x1c', '7Z', '.7z'),
                          (b'BZh', 'BZ2', '.bz2'), (b'PK\x05\x06', 'ZIP-EOCD', '.zip')]:
    idx = lsb_bytes.find(sig)
    if idx != -1:
        print(f"FOUND {name} at offset {idx}")
    else:
        print(f"NO {name} found")

# Look for long strings using byte-level check
print("\n=== String search ===")
strings = []
current = []
for b in lsb_bytes:
    # Check if byte is printable ASCII
    if 32 <= b <= 126:
        current.append(chr(b))
    else:
        if len(current) >= 6:
            strings.append((''.join(current), 
                          lsb_bytes.find(bytes(ord(c) for c in current[:4]))))
        current = []
if len(current) >= 6:
    strings.append((''.join(current), -1))

strings.sort(key=lambda x: len(x[0]), reverse=True)
for s, offset in strings[:10]:
    print(f"  len={len(s):3d}: '{s}'")

# Look for base64 strings (A-Za-z0-9+/=)
b64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
current_b64 = []
b64_strings = []
for b in lsb_bytes:
    if chr(b) in b64_chars:
        current_b64.append(chr(b))
    else:
        if len(current_b64) >= 16:
            b64_strings.append(''.join(current_b64))
        current_b64 = []
if len(current_b64) >= 16:
    b64_strings.append(''.join(current_b64))

print(f"\n=== Base64 strings (>=16 chars): {len(b64_strings)} ===")
for s in b64_strings[:10]:
    print(f"  len={len(s)}: '{s[:100]}'")

# Also check hex character strings
hex_set = set('0123456789abcdefABCDEF')
current_hex = []
hex_strings = []
for b in lsb_bytes:
    if chr(b) in hex_set:
        current_hex.append(chr(b))
    else:
        if len(current_hex) >= 16:
            hex_strings.append(''.join(current_hex))
        current_hex = []
if len(current_hex) >= 16:
    hex_strings.append(''.join(current_hex))

print(f"\n=== Hex strings (>=16 chars): {len(hex_strings)} ===")
for s in hex_strings[:10]:
    print(f"  len={len(s)}: '{s[:100]}'")

# Search for potential password patterns
# Passwords often contain a mix of upper/lower/digits
import string
pwd_chars = set(string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{}|;:,.<>?/~`')
current_pwd = []
pwd_strings = []
for b in lsb_bytes:
    if chr(b) in pwd_chars:
        current_pwd.append(chr(b))
    else:
        if 6 <= len(current_pwd) <= 40:
            has_upper = any(c.isupper() for c in current_pwd)
            has_lower = any(c.islower() for c in current_pwd)
            has_digit = any(c.isdigit() for c in current_pwd)
            if has_upper and has_lower and has_digit or len(current_pwd) >= 8:
                pwd_strings.append(''.join(current_pwd))
        current_pwd = []
if 6 <= len(current_pwd) <= 40:
    has_upper = any(c.isupper() for c in current_pwd)
    has_lower = any(c.islower() for c in current_pwd)
    has_digit = any(c.isdigit() for c in current_pwd)
    if has_upper and has_lower and has_digit or len(current_pwd) >= 8:
        pwd_strings.append(''.join(current_pwd))

print(f"\n=== Potential passwords: {len(pwd_strings)} ===")
for s in pwd_strings[:30]:
    print(f"  len={len(s)}: '{s}'")
