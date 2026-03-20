# compress.py
# LZSS compression — no external libraries needed
# Compatible with Heatshrink on STM32 (window=8, lookahead=4)

import os

# ================= LZSS CONFIG =================
LZSS_WINDOW    = 256   # 2^8  — search buffer size
LZSS_MIN_MATCH = 3     # minimum bytes to bother with a back-reference
LZSS_MAX_MATCH = 18    # maximum match length (4-bit lookahead = 15 + MIN)

# ================= LZSS COMPRESS =================
def lzss_compress(data: bytes) -> bytes:
    """
    LZSS compression compatible with Heatshrink (window=8, lookahead=4).
    Output format:
      bit = 0 → next byte is a literal
      bit = 1 → next 12 bits = (offset 8b | length 4b) back-reference
    Packed into bytes, MSB first. Trailing bits padded with 0.
    """
    src   = data
    n     = len(src)
    i     = 0
    bits  = [] # for flag
    extra = [] # for shunk

    while i < n:
        best_len = 0
        best_off = 0

        win_start = max(0, i - LZSS_WINDOW)
        for j in range(win_start, i):
            length = 0
            while (length < LZSS_MAX_MATCH and
                   i + length < n and
                   src[j + length] == src[i + length]):
                length += 1
                if j + length >= i:
                    break
            if length > best_len:
                best_len = length
                best_off = i - j

        if best_len >= LZSS_MIN_MATCH:
            bits.append(1)
            extra.append((best_off - 1) & 0xFF)
            extra.append((best_len - LZSS_MIN_MATCH) & 0x0F)
            i += best_len
        else:
            bits.append(0)
            extra.append(src[i])
            i += 1

    output    = bytearray()
    bit_buf   = 0
    bit_count = 0
    data_buf  = bytearray()
    ei        = 0

    for flag in bits:
        bit_buf    = (bit_buf << 1) | flag
        bit_count += 1

        if flag == 1:
            data_buf.append(extra[ei]); ei += 1
            data_buf.append(extra[ei]); ei += 1
        else:
            data_buf.append(extra[ei]); ei += 1

        if bit_count == 8:
            output.append(bit_buf)
            output.extend(data_buf)
            bit_buf   = 0
            bit_count = 0
            data_buf  = bytearray()

    if bit_count > 0:
        bit_buf <<= (8 - bit_count)
        output.append(bit_buf)
        output.extend(data_buf)

    return bytes(output)

# ================= LZSS DECOMPRESS =================
def lzss_decompress(data: bytes, original_size: int) -> bytes:
    """
    LZSS decompression — mirrors lzss_compress() exactly.
    Input : compressed bytes + original size (to know when to stop)
    Output: original raw bytes
    """
    output   = bytearray()
    src      = data
    n        = len(src)
    i        = 0  # byte index in compressed stream
    bit_buf  = 0
    bit_pos  = 0  # how many bits left in current bit_buf

    while len(output) < original_size:
        # Refill bit buffer if empty
        if bit_pos == 0:
            if i >= n:
                break
            bit_buf = src[i]
            i      += 1
            bit_pos = 8

        # Read 1 flag bit (MSB first)
        flag    = (bit_buf >> 7) & 1
        bit_buf = (bit_buf << 1) & 0xFF
        bit_pos -= 1

        if flag == 0:
            # Literal — next byte is raw data
            if i >= n:
                break
            output.append(src[i])
            i += 1
        else:
            # Back-reference — next 2 bytes = offset(8b) + length(4b)
            if i + 1 >= n:
                break
            offset_val = src[i];     i += 1
            length_val = src[i];     i += 1

            offset = offset_val + 1
            length = length_val + LZSS_MIN_MATCH

            # Copy from already decompressed output
            start = len(output) - offset
            for k in range(length):
                output.append(output[start + k])

    return bytes(output)
# ================= TEST =================
if __name__ == "__main__":

    TEST_BIN = r"C:\Users\HP\Documents\work_space\Embedded_Secure_Encryp_Comp\Application\Debug\Application.bin"
    with open(TEST_BIN, "rb") as f:
        original = f.read()

    print(f"Original size : {len(original)} bytes")

    # Compress
    compressed = lzss_compress(original)
    ratio      = len(compressed) / len(original) * 100
    print(f"Compressed    : {len(compressed)} bytes ({ratio:.1f}%)")

    # Decompress
    recovered = lzss_decompress(compressed, len(original))
    print(f"Decompressed  : {len(recovered)} bytes")

    # Verify
    if recovered == original:
        print("[TEST] PASS")
    else:
        # Find first difference
        print(f"[TEST] FAIL")
        if len(original) != len(recovered):
            print(f"[TEST] Size mismatch: original={len(original)} recovered={len(recovered)}")