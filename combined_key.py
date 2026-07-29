hex_bytes = bytes.fromhex('260d1637041e0414111f100b070608011e151d000c0909190a33')

# ONELASTLIGHT (12) + Final_Rehearsal (14) = 26 exactly!
key = b"ONELASTLIGHTFinal_Rehearsal"
print(f"Key: '{key.decode()}' ({len(key)} chars)")

result = bytes([a ^ b for a, b in zip(hex_bytes, key)])
print(f"Result: {result}")
try:
    r = result.decode('ascii', errors='replace')
    print(f"ASCII: {r}")
except:
    pass

# Also try variations
variations = [
    b"ONELASTLIGHTFinalRehearsl",  # 25
    b"ONELASTLIGHTFINALREHEARS",  # 24
    b"ONELASTLIGHTFinal_Rehears",
    b"Final_RehearsalONELASTLIGH", # Reverse order
    b"FinalRehearsalONELASTLIGHT", # No underscore
]

for k in variations:
    if len(k) == 26:
        res = bytes([a ^ b for a, b in zip(hex_bytes, k)])
        try:
            r = res.decode('ascii', errors='replace')
            print(f"'{k.decode()}' -> '{r}'")
        except:
            pass
    else:
        # Pad to 26
        kp = k + b'\x00' * (26 - len(k))
        res = bytes([a ^ b for a, b in zip(hex_bytes, kp)])
        try:
            r = res.decode('ascii', errors='replace')
            print(f"'{k.decode()}' (padded) -> '{r}'")
        except:
            pass
