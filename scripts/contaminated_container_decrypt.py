import json
import hashlib
from pathlib import Path
from Crypto.Cipher import AES

HEADER = b'DCLIC-V1\x00'

def load_license(path, fragment1, fragment2):
    blob = Path(path).read_bytes()
    if not blob.startswith(HEADER):
        raise ValueError('unsupported record')
    start = len(HEADER)
    counter = blob[start : start+16]
    payload = blob[start+16 : ]
    
    secret = hashlib.sha256( (fragment1 + fragment2).encode('utf-8') ).digest()
    
    cipher = AES.new(secret, AES.MODE_CTR, nonce=b'', initial_value=counter)
    
    decrypted = cipher.decrypt(payload)
    try:
        return decrypted.decode('utf-8')
    except Exception as e:
        return decrypted

print(load_license('license.dat', '1m4g3_l4y3r5_', 'r3m3mb3r'))
