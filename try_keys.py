hex_bytes = bytes.fromhex('260d1637041e0414111f100b070608011e151d000c0909190a33')
keys = [
    'The Final Rehearsal',
    'THE FINAL REHEARSAL',
    'TheFinalRehearsal',
    'THEFINALREHEARSAL',
    'the final rehearsal',
    'thefinalrehearsal',
    'Final Rehearsal',
    'FINAL REHEARSAL',
    'FinalRehearsal',
    'FINALREHEARSAL',
    'ONELASTLIGHT',
]
for k in keys:
    kb = k.encode()
    key = (kb * ((26 // len(kb)) + 2))[:26]
    res = bytes([a ^ b for a, b in zip(hex_bytes, key)])
    try:
        r = res.decode('ascii', errors='replace')
        has_brace = '{' in r and '}' in r
        printable = all(32 <= c <= 126 for c in res)
        marker = ' <-- FLAG!' if has_brace else ''
        if printable or has_brace:
            print(f"'{k}' -> '{r}'{marker}")
    except:
        pass
