"""stego.py
Consolidated Module 5 Steganography & Verification Layer:
1. Robust Layer: Quantization Index Modulation (QIM) in 8x8 DCT domain (survives JPEG).
2. Fragile Layer: Key-seeded LSB embedding with 32x32 block tamper detection.
3. Payload: RSA signature + Geffe stream encryption + 7x majority-voting redundancy.
4. Public-Key Steganography: RSA-wrapped stego seed.
5. Verification: Signature check, block tamper heatmap, and categorical verdict.
"""

import cv2
import zlib
import difflib
import numpy as np
from PIL import Image, ImageDraw
from typing import Dict, Tuple, Optional

from certificate import BLOCK_SIZE, FIELD_LAYOUT
from crypto import (
    sha256, rsa_sign, rsa_verify, rsa_wrap_key, rsa_unwrap_key, geffe_encrypt
)


# ==========================================
# 1. Payload Framing & 7x Majority Voting
# ==========================================
def build_payload(details: dict, issuer_priv: dict, session_key: bytes, redundancy: int = 7) -> list:
    """Signs, encrypts, and packages the student record with 7x redundancy."""
    record_str = f"{details['name']}|{details['roll']}|{details['degree']}|{details['year']}|{details['cgpa']}"
    record_bytes = record_str.encode("utf-8")

    # RSA digital signature over SHA-256 digest
    sig = rsa_sign(record_bytes, issuer_priv)

    # Encrypt (length + record + signature) with Geffe stream cipher
    bundle = len(record_bytes).to_bytes(2, "big") + record_bytes + sig
    ciphertext = geffe_encrypt(bundle, session_key)

    # Frame with 'TL' magic header and CRC-32
    crc = zlib.crc32(ciphertext).to_bytes(4, "big")
    packet = b"TL" + len(ciphertext).to_bytes(2, "big") + crc + ciphertext

    # Convert to bits
    bits = []
    for b in packet:
        for shift in range(7, -1, -1):
            bits.append((b >> shift) & 1)

    # 7x redundancy
    return bits * redundancy


def parse_payload(repeated_bits: list, session_key: bytes, issuer_pub: dict, redundancy: int = 7) -> Tuple[Optional[dict], bool]:
    """Applies bitwise majority voting across 7 copies, decrypts, and checks RSA signature."""
    if len(repeated_bits) % redundancy != 0 or len(repeated_bits) < 64:
        return None, False

    single_len = len(repeated_bits) // redundancy
    # Majority vote
    voted_bits = []
    threshold = redundancy / 2.0
    for i in range(single_len):
        votes = sum(repeated_bits[r * single_len + i] for r in range(redundancy))
        voted_bits.append(1 if votes > threshold else 0)

    # Convert bits back to bytes
    packet = bytearray()
    for i in range(0, len(voted_bits) - 7, 8):
        byte_val = 0
        for b in voted_bits[i:i + 8]:
            byte_val = (byte_val << 1) | b
        packet.append(byte_val)

    if len(packet) < 8 or packet[:2] != b"TL":
        return None, False

    c_len = int.from_bytes(packet[2:4], "big")
    stored_crc = int.from_bytes(packet[4:8], "big")
    ciphertext = bytes(packet[8:8 + c_len])

    if zlib.crc32(ciphertext) != stored_crc:
        return None, False

    # Decrypt with Geffe
    bundle = geffe_encrypt(ciphertext, session_key)
    rec_len = int.from_bytes(bundle[:2], "big")
    record_bytes = bundle[2:2 + rec_len]
    sig = bundle[2 + rec_len:]

    sig_valid = rsa_verify(record_bytes, sig, issuer_pub)
    parts = record_bytes.decode("utf-8", errors="replace").split("|")
    if len(parts) < 5:
        return None, False

    record_dict = {"name": parts[0], "roll": parts[1], "degree": parts[2], "year": parts[3], "cgpa": parts[4]}
    return record_dict, sig_valid


# ==========================================
# 2. Robust DCT Layer (Certificate ID)
# ==========================================
def embed_dct_id(image: Image.Image, cert_id: str, q: float = 20.0) -> Image.Image:
    """Embeds Certificate ID into 8x8 DCT mid-frequency coefficient (3, 2) of Y channel using QIM."""
    arr = np.array(image, dtype=np.uint8)
    ycrcb = cv2.cvtColor(arr, cv2.COLOR_RGB2YCrCb)
    y = ycrcb[:, :, 0].astype(np.float32)

    # ID to bits
    id_bytes = cert_id.encode("utf-8")
    bits = [int((len(id_bytes) >> (7 - i)) & 1) for i in range(8)]
    for b in id_bytes:
        for shift in range(7, -1, -1):
            bits.append((b >> shift) & 1)

    h, w = y.shape
    num_blocks = (h // 8) * (w // 8)
    bpb = num_blocks // len(bits)
    if bpb < 1: return image

    bit_idx, rep = 0, 0
    for br in range(h // 8):
        for bc in range(w // 8):
            if bit_idx >= len(bits): break
            blk = y[br*8:(br+1)*8, bc*8:(bc+1)*8]
            dct = cv2.dct(blk)

            # QIM: even multiple for bit 0, odd for bit 1
            target_bit = bits[bit_idx]
            k = int(round(dct[3, 2] / q))
            if (k % 2) != target_bit:
                k += 1 if dct[3, 2] >= k * q else -1
            dct[3, 2] = float(k * q)

            y[br*8:(br+1)*8, bc*8:(bc+1)*8] = cv2.idct(dct)
            rep += 1
            if rep >= bpb:
                rep = 0
                bit_idx += 1
        if bit_idx >= len(bits): break

    ycrcb[:, :, 0] = np.clip(y, 0, 255).astype(np.uint8)
    return Image.fromarray(cv2.cvtColor(ycrcb, cv2.COLOR_YCrCb2RGB), "RGB")


def extract_dct_id(image: Image.Image, q: float = 20.0) -> Optional[str]:
    """Extracts Certificate ID using majority voting across redundant 8x8 DCT blocks."""
    arr = np.array(image, dtype=np.uint8)
    ycrcb = cv2.cvtColor(arr, cv2.COLOR_RGB2YCrCb)
    y = ycrcb[:, :, 0].astype(np.float32)

    h, w = y.shape
    total_blocks = (h // 8) * (w // 8)
    # Expected: 8 bits len + 12 chars * 8 = 104 bits
    expected_bits = 104
    bpb = total_blocks // expected_bits
    if bpb < 1: return None

    votes = []
    recovered_bits = []
    for br in range(h // 8):
        for bc in range(w // 8):
            blk = y[br*8:(br+1)*8, bc*8:(bc+1)*8]
            dct = cv2.dct(blk)
            bit = int(round(dct[3, 2] / q)) % 2
            votes.append(bit)
            if len(votes) == bpb:
                recovered_bits.append(1 if sum(votes) > bpb / 2.0 else 0)
                votes = []
                if len(recovered_bits) == expected_bits: break
        if len(recovered_bits) == expected_bits: break

    # Convert to string
    try:
        val = bytearray()
        for i in range(0, len(recovered_bits), 8):
            b = 0
            for bit in recovered_bits[i:i+8]:
                b = (b << 1) | bit
            val.append(b)
        id_len = val[0]
        if id_len > 0 and len(val) >= 1 + id_len:
            return bytes(val[1:1+id_len]).decode("utf-8")
    except Exception:
        pass
    return None


# ==========================================
# 3. Fragile LSB Layer & 32x32 Block Checksums
# ==========================================
def embed_lsb_and_checksums(image: Image.Image, payload_bits: list, stego_seed: int) -> Image.Image:
    """Embeds fragile payload and computes 32-bit checksums for every 32x32 image block."""
    arr = np.array(image, dtype=np.uint8)
    h, w, _ = arr.shape
    num_rows, num_cols = h // BLOCK_SIZE, w // BLOCK_SIZE

    # Exclude row 0 checksums and row 1 seed header
    allowed = np.ones((h, w), dtype=bool)
    allowed[0::BLOCK_SIZE, :32] = False
    allowed[1, :2048] = False

    # Key-seeded pixel positions
    rng = np.random.default_rng(stego_seed)
    valid_coords = np.argwhere(allowed)
    rng.shuffle(valid_coords)

    # 1. Embed length (32 bits) + payload bits
    full_bits = [int((len(payload_bits) >> (31 - i)) & 1) for i in range(32)] + payload_bits
    for bit, (y, x) in zip(full_bits, valid_coords):
        arr[y, x, 0] = (arr[y, x, 0] & 0xFE) | bit

    # 2. Block Checksums: hash upper 7 bit-planes of each 32x32 block and store in row 0 LSB
    for r in range(num_rows):
        for c in range(num_cols):
            y0, x0 = r * BLOCK_SIZE, c * BLOCK_SIZE
            block_upper7 = (arr[y0:y0+BLOCK_SIZE, x0:x0+BLOCK_SIZE] >> 1).tobytes()
            chk = int.from_bytes(sha256(block_upper7)[:4], "big")
            for bit_pos in range(32):
                bit = (chk >> (31 - bit_pos)) & 1
                arr[y0, x0 + bit_pos, 0] = (arr[y0, x0 + bit_pos, 0] & 0xFE) | bit

    return Image.fromarray(arr, "RGB")


def extract_lsb(image: Image.Image, stego_seed: int) -> list:
    """Extracts payload bits using the stego seed."""
    arr = np.array(image, dtype=np.uint8)
    h, w, _ = arr.shape

    allowed = np.ones((h, w), dtype=bool)
    allowed[0::BLOCK_SIZE, :32] = False
    allowed[1, :2048] = False

    rng = np.random.default_rng(stego_seed)
    valid_coords = np.argwhere(allowed)
    rng.shuffle(valid_coords)

    # Read 32-bit length
    length = 0
    for i in range(32):
        y, x = valid_coords[i]
        length = (length << 1) | int(arr[y, x, 0] & 1)

    if length <= 0 or length > 50000:
        return []

    payload = []
    for i in range(32, 32 + length):
        y, x = valid_coords[i]
        payload.append(int(arr[y, x, 0] & 1))
    return payload


def verify_blocks(image: Image.Image) -> Tuple[np.ndarray, Image.Image]:
    """Recomputes block checksums to detect local tampering. Returns boolean grid and red heatmap."""
    arr = np.array(image, dtype=np.uint8)
    h, w, _ = arr.shape
    num_rows, num_cols = h // BLOCK_SIZE, w // BLOCK_SIZE
    tamper_grid = np.zeros((num_rows, num_cols), dtype=bool)

    base = image.convert("RGBA")
    overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    for r in range(num_rows):
        for c in range(num_cols):
            y0, x0 = r * BLOCK_SIZE, c * BLOCK_SIZE
            stored_chk = 0
            for bit_pos in range(32):
                stored_chk = (stored_chk << 1) | int(arr[y0, x0 + bit_pos, 0] & 1)

            actual_chk = int.from_bytes(sha256((arr[y0:y0+BLOCK_SIZE, x0:x0+BLOCK_SIZE] >> 1).tobytes())[:4], "big")
            if stored_chk != actual_chk:
                tamper_grid[r, c] = True
                draw.rectangle([x0, y0, x0+BLOCK_SIZE, y0+BLOCK_SIZE], fill=(255, 0, 0, 120), outline=(255, 0, 0, 240), width=2)

    heatmap = Image.alpha_composite(base, overlay).convert("RGB")
    return tamper_grid, heatmap


# ==========================================
# 4. Public-Key Steganography & Pipeline
# ==========================================
def issue_certificate_full(details: dict, issuer_priv: dict, verifier_pub: dict, session_key: bytes) -> Image.Image:
    """Full issuance: Render -> Embed DCT ID -> Wrap Stego Seed -> Embed Fragile LSB & Checksums."""
    from certificate import generate_certificate
    cert = generate_certificate(details)

    # 1. Robust DCT layer
    cert_dct = embed_dct_id(cert, details.get("cert_id", "TL-2026-0123"))

    # 2. Stego seed wrapped with verifier's RSA public key (row 1 LSB)
    seed_bytes = np.random.bytes(16)
    wrapped_seed = rsa_wrap_key(seed_bytes, verifier_pub)
    seed_int = int.from_bytes(seed_bytes[:8], "big")

    arr = np.array(cert_dct, dtype=np.uint8)
    bit_idx = 0
    for b in wrapped_seed:
        for shift in range(7, -1, -1):
            arr[1, bit_idx, 0] = (arr[1, bit_idx, 0] & 0xFE) | ((b >> shift) & 1)
            bit_idx += 1
    cert_with_seed = Image.fromarray(arr, "RGB")

    # 3. Fragile LSB payload
    payload_bits = build_payload(details, issuer_priv, session_key, redundancy=7)
    final_stego = embed_lsb_and_checksums(cert_with_seed, payload_bits, stego_seed=seed_int)
    return final_stego


def verify_certificate_full(image: Image.Image, verifier_priv: dict, issuer_pub: dict, session_key: bytes) -> dict:
    """Full forensic verification: checks signature, block checksums, DCT layer, and outputs verdict."""
    dct_id = extract_dct_id(image)
    tamper_grid, heatmap = verify_blocks(image)
    failed_blocks = int(np.count_nonzero(tamper_grid))

    # Unwrap seed from row 1
    arr = np.array(image, dtype=np.uint8)
    key_bytes = (verifier_priv["bits"] + 7) // 8
    wrapped_seed_bits = [int(arr[1, i, 0] & 1) for i in range(key_bytes * 8)]
    wrapped_seed = bytearray()
    for i in range(0, len(wrapped_seed_bits), 8):
        b = 0
        for bit in wrapped_seed_bits[i:i+8]: b = (b << 1) | bit
        wrapped_seed.append(b)

    hidden_record, sig_valid = None, False
    try:
        seed_bytes = rsa_unwrap_key(bytes(wrapped_seed), verifier_priv, out_len=16)
        seed_int = int.from_bytes(seed_bytes[:8], "big")
        payload_bits = extract_lsb(image, seed_int)
        hidden_record, sig_valid = parse_payload(payload_bits, session_key, issuer_pub)
    except Exception:
        pass

    # Verdict Logic
    if sig_valid and failed_blocks == 0:
        verdict = "GENUINE"
        reason = "Digital signature is valid and all 1,800 image blocks are authentic."
    elif sig_valid and failed_blocks > 0:
        verdict = "FORGED / EDITED"
        reason = f"Signature valid, but {failed_blocks} image blocks have been digitally tampered."
    elif (not sig_valid) and (dct_id is not None):
        verdict = "DAMAGED ORIGINAL"
        reason = f"Fragile layer destroyed by recompression/resizing, but robust DCT recovered Certificate ID: {dct_id}."
    else:
        verdict = "NOT A TRUSTLENS CERTIFICATE"
        reason = "No authentic watermark or cryptographic signature found."

    return {
        "verdict": verdict,
        "reason": reason,
        "sig_valid": sig_valid,
        "failed_blocks": failed_blocks,
        "dct_id": dct_id,
        "hidden_record": hidden_record,
        "heatmap": heatmap,
        "tamper_grid": tamper_grid
    }
