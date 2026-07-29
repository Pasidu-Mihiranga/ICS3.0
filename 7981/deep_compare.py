import struct, numpy as np

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
lsb_bits = (samples & 1).astype(np.uint8)
padded = np.pad(lsb_bits, (0, 8 - len(lsb_bits) % 8) if len(lsb_bits) % 8 else (0, 0))
lsb_bytes = np.packbits(padded).tobytes()
lsb_bytes = lsb_bytes[:len(lsb_bits) // 8]

block_size = 441
n_blocks = len(lsb_bytes) // block_size
print(f"Total blocks: {n_blocks} of {block_size} bytes each")

# Compare all blocks to block 0
block0 = lsb_bytes[:block_size]
diff_blocks = []
for i in range(1, n_blocks):
    block_i = lsb_bytes[i*block_size:(i+1)*block_size]
    if block_i != block0:
        diff_positions = [j for j in range(block_size) if block_i[j] != block0[j]]
        diff_blocks.append((i, diff_positions))
        if len(diff_blocks) <= 10:
            print(f"Block {i}: differs at {len(diff_positions)} positions: {diff_positions[:10]}")

if not diff_blocks:
    print("ALL BLOCKS ARE IDENTICAL")
    
# Just show a sampling
print(f"\nBlock 0: {block0[:50].hex()}")
print(f"Block 1: {lsb_bytes[block_size:block_size+50].hex()}")
print(f"Block 100: {lsb_bytes[100*block_size:100*block_size+50].hex()}")
print(f"Block 1994: {lsb_bytes[1994*block_size:1994*block_size+50].hex()}")

# Compare
for i, off in [(1, block_size), (100, 100*block_size), (1994, 1994*block_size)]:
    match = lsb_bytes[off:off+50] == block0[:50]
    print(f"Block {i} first 50 bytes match: {match}")

# Check if the passphrase might be formed from bits collected differently
# What if each block contributes one bit to the passphrase?
print("\n=== Cross-block bit extraction ===")
# For each byte position in the block, check if it varies across blocks
varies = [False] * block_size
for pos in range(block_size):
    base_val = lsb_bytes[pos]
    for blk in range(1, min(100, n_blocks)):
        if lsb_bytes[blk * block_size + pos] != base_val:
            varies[pos] = True
            break
print(f"Bytes that vary: {sum(varies)}/{block_size}")

if sum(varies) == 0:
    print("No bytes vary - all blocks truly identical")
    
    # If all blocks identical, the passphrase must be WITHIN the single block
    # Try to decode the block as different encodings
    
    # Try reading bits 0,2,4,6 of each sample (even bits)
    even_bits = (samples & 0x55).astype(np.uint8)  # binary 01010101
    print(f"\nEven bits extracted")
    
    # Try every other bit
    for bitmask, name in [(0x01, 'bit0'), (0x02, 'bit1'), (0x04, 'bit2'), 
                            (0x0F, 'bits0-3'), (0xF0, 'bits4-7')]:
        if name in ['bit0', 'bit1', 'bit2']:
            vals = (samples & bitmask) >> (0 if name == 'bit0' else 1 if name == 'bit1' else 2)
            bits = vals.astype(np.uint8)
            padded_b = np.pad(bits, (0, 8 - len(bits) % 8) if len(bits) % 8 else (0, 0))
            byte_data = np.packbits(padded_b).tobytes()
            byte_data = byte_data[:len(bits) // 8]
            blk = byte_data[:441]
            text = ''.join(chr(b) if 32<=b<=126 else '.' for b in blk[:100])
            for sig, sig_name in [(b'PK\x03\x04', 'ZIP'), (b'\x1f\x8b\x08', 'GZIP'),
                                    (b'iCS{', 'FLAG'), (b'ICS{', 'FLAG_ICS')]:
                if sig in blk:
                    print(f"  {name} at 441-byte: FOUND {sig_name}!")
                    if sig_name.startswith('FLAG'):
                        end = blk.find(b'}', blk.index(sig))
                        if end != -1:
                            print(f"    {blk[blk.index(sig):end+1].decode()}")
            print(f"  {name}: text = {text[:60]}")
