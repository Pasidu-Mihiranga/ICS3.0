#!/usr/bin/env python3
"""The Man on the Sealed Train - full solve from sealed_train.zip.

Six stages, each producing the key for the next:
    A1Z26 -> Vigenere -> Caesar -> ZipCrypto + MD5 lookup -> ZipCrypto ->
    SHA-256 counter-mode XOR -> speech + final archive mark (hex).
"""
import base64, hashlib, io, re, struct, sys, zipfile

PATH = sys.argv[1] if len(sys.argv) > 1 else "sealed_train.zip"
outer = zipfile.ZipFile(PATH)
read = lambda z, n, pw=None: z.read(n, pwd=pw)

# --- stage 1: A1Z26 ---------------------------------------------------------
letter = read(outer, "childhood_letter.txt").decode()
nums = [int(x) for x in re.search(r"((?:\d+\s*-\s*)+\d+)", letter).group(1).split("-")]
key = "".join(chr(64 + n) for n in nums)
assert key == "REVOLUTION", key

# --- stage 2: Vigenere (verification only) ----------------------------------
def vigenere(ct, k):
    out, i = [], 0
    for c in ct:
        if c.isalpha():
            out.append(chr((ord(c.upper()) - 65 - (ord(k[i % len(k)]) - 65)) % 26 + 65)); i += 1
        else:
            out.append(c)
    return "".join(out)

note = read(outer, "prisoner_note.txt").decode()
print("stage2:", vigenere(note.split("\n")[0].strip(), key))

# --- stage 3: Caesar, shift = len(index_term) -------------------------------
shift = len(re.search(r"index_term\s*=\s*(\w+)", note).group(1))       # CAPITALISM -> 10
caesar = lambda t: "".join(chr((ord(c) - 65 - shift) % 26 + 65) if c.isalpha() else c for c in t)
diary = read(outer, "exile_diary.txt").decode()
plain = "\n".join(caesar(l) for l in diary.split("\n")
                  if l.strip() and l.strip() == l.strip().upper() and any(c.isalpha() for c in l))
print("stage3:\n" + plain)
city = "ZURICH"                                    # six letters, lake, German, starts with Z

# --- stage 4: ZipCrypto + MD5 lookup ----------------------------------------
clip = zipfile.ZipFile(io.BytesIO(read(outer, "newspaper_clipping.zip")))
news = read(clip, "newspaper_clipping.txt", city.encode()).decode()
cities = read(clip, "cities.txt", city.encode()).decode().split()
mark = re.search(r"\b([0-9a-f]{32})\b", news).group(1)
dest = next(c for c in cities if hashlib.md5(c.encode()).hexdigest() == mark)
assert dest == "PETROGRAD", dest

# --- stage 5: manifest ------------------------------------------------------
man_zip = zipfile.ZipFile(io.BytesIO(read(clip, "sealed_train_manifest.zip", city.encode())))
man = read(man_zip, "train_manifest.txt", dest.encode()).decode()
route = base64.b64decode(re.search(r"Route note:\s*(\S+)", man).group(1)).decode()   # SEALED TRAIN
d, m, y = map(int, re.search(r"NEW STYLE\):\s*(\d+)-(\d+)-(\d+)", man).groups())
d -= 13                                            # Julian: 13 days behind
date = bytes([d, m, y // 100, y % 100])            # 03 04 13 11

# --- stage 6: SHA-256 counter-mode XOR --------------------------------------
seed = f"{dest}|{route}|".encode() + date
enc = read(outer, "final_speech.enc")
ks = b"".join(hashlib.sha256(seed + struct.pack(">I", i)).digest()
              for i in range((len(enc) + 31) // 32))
pt = bytes(a ^ b for a, b in zip(enc, ks))
print("\n" + pt.decode())

flag = bytes.fromhex(re.search(r"\b([0-9A-F]{40,})\b", pt.decode()).group(1)).decode()
print("FLAG:", flag)          # iCS{P0W3R_W45_1N_7H3_5P33CH}  <- lowercase i is intentional
