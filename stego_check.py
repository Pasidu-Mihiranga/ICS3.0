# Try LSB steganography on the dressing room photo
# Also check for data appended after JPEG EOF (FF D9)

with open('D:/test/CTF/The Final Rehearsal/dressing_room.jpg', 'rb') as f:
    jpg_data = f.read()

print(f"JPEG size: {len(jpg_data)}")

# Find JPEG end marker
idx = jpg_data.find(b'\xff\xd9')
if idx >= 0:
    after_jpg = jpg_data[idx+2:]
    print(f"JPEG ends at offset {idx}")
    print(f"Data after JPEG EOF: {len(after_jpg)} bytes")
    if len(after_jpg) > 0:
        print(f"  Hex: {after_jpg.hex()}")
        print(f"  ASCII: {repr(after_jpg[:200])}")
    else:
        print("  No trailing data")
else:
    print("JPEG EOF not found (unusual)")

# Try LSB extraction from pixel data
# Find Start of Scan (SOS) marker 0xFFDA
sos_idx = jpg_data.find(b'\xff\xda')
print(f"\nSOS marker at offset {sos_idx}")

# Simple LSB extraction on JPEG byte data
# Skip header bytes, extract LSB of each pixel byte after SOS
if sos_idx >= 0:
    pixel_data = jpg_data[sos_idx+2:]
    # Extract first N bytes of LSB data
    lsb_bits = ''
    for i, byte in enumerate(pixel_data[:2000]):
        lsb_bits += str(byte & 1)
        if i % 100 == 0 and i > 0:
            # Convert to bytes every 8 bits
            pass
    
    # Convert LSB bits to bytes
    lsb_bytes = bytearray()
    for i in range(0, len(lsb_bits) - 7, 8):
        byte_val = int(lsb_bits[i:i+8], 2)
        lsb_bytes.append(byte_val)
    
    # Check if readable
    printable = lsb_bytes[:100]
    print(f"First 100 LSB bytes: {repr(printable)}")
    try:
        decoded = printable.decode('ascii')
        if decoded.isprintable():
            print(f"  Readable: {decoded}")
    except:
        pass

# ALSO: check if the XOR key should be the lighting plan content
# "One light or the other" - maybe the two lighting cues?
# From LIGHTINGTXT: Cue 1: House lights out, Cue 7: Blackout
# "One light" = ONELASTLIGHT, "the other" = BLACKOUT?

# Try XOR with BLACKOUT
hex_bytes = bytes.fromhex("260d1637041e0414111f100b070608011e151d000c0909190a33")
blackout_key = (b"BLACKOUT" * 4)[:26]
result = bytes([a ^ b for a, b in zip(hex_bytes, blackout_key)])
print(f"\nXOR hex with BLACKOUT: {result}")
print(f"  ASCII: {result.decode('ascii', errors='replace')}")

# Also try WITHOUT the lighting cue prefix
key = (b"ONELASTLIGHT" * 3)[:26]
result = bytes([a ^ b for a, b in zip(hex_bytes, key)])
print(f"XOR hex with ONELASTLIGHT: {result}")
print(f"  ASCII: {result.decode('ascii', errors='replace')}")

# What if we XOR with the FULL UserComment?
key = (b"Lighting cue: ONELASTLIGHT / repeat until blackout" * 1)[:26]
result = bytes([a ^ b for a, b in zip(hex_bytes, key)])
print(f"XOR hex with UserComment: {result}")
print(f"  ASCII: {result.decode('ascii', errors='replace')}")
