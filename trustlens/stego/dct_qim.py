"""Step 5: Robust DCT Quantization Index Modulation (QIM) Steganography.
Implements:
1. RGB to YCbCr conversion (operating exclusively on luminance Y channel).
2. 8x8 block 2D DCT (via cv2.dct).
3. Mid-frequency coefficient selection (e.g., (3, 2) and (2, 3)).
4. Quantization Index Modulation (QIM) with step size Q (default Q=20).
5. 250x+ redundancy across 28,800 blocks with majority voting to survive JPEG compression.
6. Certificate ID payload framing with CRC-16.
"""

import cv2
import zlib
import numpy as np
from PIL import Image
from typing import List, Tuple, Optional

# Mid-frequency DCT coefficient positions (row, col) in 8x8 block
CARRIER_COEFFS = [(3, 2), (2, 3)]
DEFAULT_Q = 20.0


def _crc16(data: bytes) -> int:
    """Computes CRC-16-CCITT checksum."""
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def cert_id_to_bits(cert_id: str) -> List[int]:
    """Encodes Certificate ID string (e.g. 'TL-2026-0123') with CRC-16 into a bit list."""
    id_bytes = cert_id.strip().encode("utf-8")
    crc = _crc16(id_bytes)
    # Pack: 1 byte len + id_bytes + 2 bytes CRC16
    packet = bytes([len(id_bytes)]) + id_bytes + bytes([(crc >> 8) & 0xFF, crc & 0xFF])
    bits = []
    for b in packet:
        for shift in range(7, -1, -1):
            bits.append((b >> shift) & 1)
    return bits


def bits_to_cert_id(bits: List[int]) -> Optional[str]:
    """Decodes bit list into Certificate ID, verifying length and CRC-16 checksum."""
    if len(bits) < 24:
        return None
    # Convert bits to bytes
    byte_vals = bytearray()
    for i in range(0, (len(bits) // 8) * 8, 8):
        val = 0
        for b in bits[i:i + 8]:
            val = (val << 1) | (b & 1)
        byte_vals.append(val)

    id_len = byte_vals[0]
    if len(byte_vals) < 1 + id_len + 2:
        return None

    id_bytes = bytes(byte_vals[1:1 + id_len])
    stored_crc = (byte_vals[1 + id_len] << 8) | byte_vals[1 + id_len + 1]
    calc_crc = _crc16(id_bytes)

    if stored_crc != calc_crc:
        return None

    try:
        return id_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None


def qim_embed_coeff(c: float, bit: int, q: float = DEFAULT_Q) -> float:
    """Quantization Index Modulation:
    Forces round(c / Q) to be even for bit 0, and odd for bit 1.
    """
    k = int(round(c / q))
    if (k % 2) != (bit & 1):
        if c >= (k * q):
            k += 1
        else:
            k -= 1
    return float(k * q)


def qim_extract_coeff(c: float, q: float = DEFAULT_Q) -> int:
    """Extracts bit from quantized DCT coefficient:
    Returns round(c / Q) mod 2.
    """
    k = int(round(c / q))
    return int(k % 2)


def embed_dct_id(
    image: Image.Image,
    cert_id: str,
    q: float = DEFAULT_Q,
    coeff_pos: Tuple[int, int] = (3, 2)
) -> Image.Image:
    """Embeds Certificate ID robustly into the DCT mid-frequency coefficients of the Y channel."""
    # Convert PIL Image to RGB OpenCV array
    rgb = np.array(image, dtype=np.uint8)
    h, w, _ = rgb.shape

    # Convert RGB to YCrCb (OpenCV uses YCrCb for Y, Cr, Cb)
    ycrcb = cv2.cvtColor(rgb, cv2.COLOR_RGB2YCrCb)
    y_channel = ycrcb[:, :, 0].astype(np.float32)

    # Encode ID into bits
    id_bits = cert_id_to_bits(cert_id)
    num_bits = len(id_bits)

    # Calculate 8x8 blocks
    block_rows = h // 8
    block_cols = w // 8
    total_blocks = block_rows * block_cols
    blocks_per_bit = total_blocks // num_bits

    if blocks_per_bit < 1:
        raise ValueError("Image too small to embed Certificate ID")

    r_c, c_c = coeff_pos
    curr_bit_idx = 0
    curr_rep_count = 0

    for br in range(block_rows):
        for bc in range(block_cols):
            if curr_bit_idx >= num_bits:
                break
            y0, x0 = br * 8, bc * 8
            blk = y_channel[y0:y0 + 8, x0:x0 + 8]
            dct_blk = cv2.dct(blk)

            target_bit = id_bits[curr_bit_idx]
            dct_blk[r_c, c_c] = qim_embed_coeff(dct_blk[r_c, c_c], target_bit, q=q)

            # Inverse DCT
            y_channel[y0:y0 + 8, x0:x0 + 8] = cv2.idct(dct_blk)

            curr_rep_count += 1
            if curr_rep_count >= blocks_per_bit:
                curr_rep_count = 0
                curr_bit_idx += 1

        if curr_bit_idx >= num_bits:
            break

    # Reconstruct YCrCb and convert back to RGB
    ycrcb[:, :, 0] = np.clip(y_channel, 0, 255).astype(np.uint8)
    stego_rgb = cv2.cvtColor(ycrcb, cv2.COLOR_YCrCb2RGB)

    return Image.fromarray(stego_rgb, mode="RGB")


def extract_dct_id(
    image: Image.Image,
    q: float = DEFAULT_Q,
    coeff_pos: Tuple[int, int] = (3, 2),
    estimated_id_len: int = 12
) -> Optional[str]:
    """Extracts Certificate ID using majority voting across redundant 8x8 DCT blocks."""
    rgb = np.array(image, dtype=np.uint8)
    h, w, _ = rgb.shape

    ycrcb = cv2.cvtColor(rgb, cv2.COLOR_RGB2YCrCb)
    y_channel = ycrcb[:, :, 0].astype(np.float32)

    block_rows = h // 8
    block_cols = w // 8
    total_blocks = block_rows * block_cols

    # Number of bits for standard ID packet: 1 byte len + 12 byte id + 2 byte crc = 15 bytes = 120 bits
    total_bits_packet = (1 + estimated_id_len + 2) * 8
    blocks_per_bit = total_blocks // total_bits_packet

    if blocks_per_bit < 1:
        return None

    r_c, c_c = coeff_pos
    recovered_bits = []
    bit_votes = []

    for br in range(block_rows):
        for bc in range(block_cols):
            y0, x0 = br * 8, bc * 8
            blk = y_channel[y0:y0 + 8, x0:x0 + 8]
            dct_blk = cv2.dct(blk)

            bit = qim_extract_coeff(dct_blk[r_c, c_c], q=q)
            bit_votes.append(bit)

            if len(bit_votes) == blocks_per_bit:
                # Majority vote
                maj_bit = 1 if sum(bit_votes) > (blocks_per_bit / 2.0) else 0
                recovered_bits.append(maj_bit)
                bit_votes = []
                if len(recovered_bits) == total_bits_packet:
                    break
        if len(recovered_bits) == total_bits_packet:
            break

    # Attempt to decode ID with CRC check
    cert_id = bits_to_cert_id(recovered_bits)
    if cert_id:
        return cert_id

    # If length varied, try adjacent lengths (e.g., 10 to 14 bytes)
    for trial_len in range(8, 16):
        trial_bits_len = (1 + trial_len + 2) * 8
        trial_bpb = total_blocks // trial_bits_len
        t_bits = []
        t_votes = []
        for br in range(block_rows):
            for bc in range(block_cols):
                y0, x0 = br * 8, bc * 8
                blk = y_channel[y0:y0 + 8, x0:x0 + 8]
                dct_blk = cv2.dct(blk)
                t_votes.append(qim_extract_coeff(dct_blk[r_c, c_c], q=q))
                if len(t_votes) == trial_bpb:
                    t_bits.append(1 if sum(t_votes) > (trial_bpb / 2.0) else 0)
                    t_votes = []
                    if len(t_bits) == trial_bits_len:
                        break
            if len(t_bits) == trial_bits_len:
                break
        res = bits_to_cert_id(t_bits)
        if res:
            return res

    return None
