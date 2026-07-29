hex_bytes = bytes.fromhex('260d1637041e0414111f100b070608011e151d000c0909190a33')
scene = b'ONELASTLIGHT'
key = (scene * 3)[:26]
flag = bytes([a ^ b for a, b in zip(hex_bytes, key)]).decode()
print(f'Flag: {flag}')
print(f'Length: {len(flag)}')
back = bytes([ord(flag[i]) ^ key[i] for i in range(26)])
print(f'Reverse check: {back.hex()}')
print(f'Original:      {hex_bytes.hex()}')
print(f'Match: {back == hex_bytes}')
print()
print('Pos | Hex  | Key | Char')
print('----|------|-----|------')
for i in range(26):
    h = hex_bytes[i]
    k = key[i]
    c = h ^ k
    print(f'{i:3} | 0x{h:02X} | {chr(k):3}  | {chr(c):3}  (0x{c:02X})')
