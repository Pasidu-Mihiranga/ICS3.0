hex_bytes = bytes.fromhex("260d1637041e0414111f100b070608011e151d000c0909190a33")

# Try alternative XOR keys — the REAL filenames
keys_to_try = {
    "Final_Rehearsal": b"Final_Rehearsal",
    "FinalRehearsal": b"FinalRehearsal",
    "VOICE_NOTE_FINAL": b"VOICE_NOTE_FINAL",
    "VOICENOTEFINAL": b"VOICENOTEFINAL",
    "Final_Rehearsal_2106": b"Final_Rehearsal 21:06",
    "ONELASTLIGHT": b"ONELASTLIGHT",
}

print("Alternative XOR key attempts:")
print("="*80)

for name, key_base in keys_to_try.items():
    key = (key_base * ((26 // len(key_base)) + 2))[:26]
    result = bytes([a ^ b for a, b in zip(hex_bytes, key)])
    try:
        readable = result.decode('ascii', errors='replace')
        if '{' in readable and '}' in readable:
            print(f"Key '{name}': {readable}  <-- FLAG FORMAT!")
        elif all(32 <= c <= 126 or c == 10 for c in result):
            print(f"Key '{name}': {readable}")
        else:
            print(f"Key '{name}': (non-printable) {result[:20].hex()}")
    except:
        print(f"Key '{name}': (decode error)")

# Also try: XOR with exact 26-byte phrases from evidence
additional = [
    b"Final_Rehearsal_21-06_CST",
    b"VOICE_NOTE_FINAL_10.37s",
    b"EMP0714_ENTRY_21.18_CST",
    b"ONELASTLIGHT_BLACKOUT",
    b"FinalRehearsalONELASTLIGH",
    b"Final_RehearsalONELASTLIG",
]

for key_base in additional:
    key = key_base[:26]
    if len(key) < 26:
        key = key + b'\x00' * (26 - len(key))
    result = bytes([a ^ b for a, b in zip(hex_bytes, key)])
    try:
        readable = result.decode('ascii', errors='replace')
        if '{' in readable and '}' in readable:
            print(f"Key '{key_base.decode()}': {readable}  <-- FLAG FORMAT!")
        elif all(32 <= c <= 126 or c == 10 for c in result):
            print(f"Key '{key_base.decode()}': {readable}")
    except:
        pass

# Also: what if XOR with the filename gives us a DIFFERENT iCS flag?
# Try Final_Rehearsal padded/truncated to 26
key = b"Final_RehearsalFinal_Rehe"
result = bytes([a ^ b for a, b in zip(hex_bytes, key)])
print(f"\nKey 'Final_RehearsalFinal_Rehe' (26): {result}")
print(f"  Hex: {result.hex()}")
try:
    print(f"  ASCII: {result.decode('ascii', errors='replace')}")
except:
    pass
