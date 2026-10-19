"""Step 2: Stego Payload Builder, Redundancy, Framing, and Majority Voting.
Packages student records with RSA signature, Geffe stream encryption, CRC-32 integrity,
and 7x bitwise majority-voting redundancy to survive local tampering.
"""

import struct
import zlib
from typing import Dict, List, Tuple, Optional
from ..crypto.lfsr import encrypt_geffe, decrypt_geffe
from ..crypto.rsa_scratch import sign, verify, RSAPrivateKey, RSAPublicKey

MAGIC = b"TL"
VERSION = 1
DEFAULT_REDUNDANCY = 7


def record_to_string(details: Dict[str, str]) -> str:
    """Formats student details into canonical record string: name|roll|degree|year|cgpa."""
    name = details.get("name", "").strip()
    roll = details.get("roll", "").strip()
    degree = details.get("degree", "").strip()
    year = details.get("year", "").strip()
    cgpa = details.get("cgpa", "").strip()
    return f"{name}|{roll}|{degree}|{year}|{cgpa}"


def string_to_record(record_str: str) -> Dict[str, str]:
    """Parses canonical record string back into dictionary."""
    parts = record_str.split("|")
    if len(parts) < 5:
        raise ValueError(f"Invalid record string format: {record_str}")
    return {
        "name": parts[0],
        "roll": parts[1],
        "degree": parts[2],
        "year": parts[3],
        "cgpa": parts[4]
    }


def to_bits(data: bytes) -> List[int]:
    """Converts bytes to a list of bits (MSB first)."""
    bits = []
    for b in data:
        for shift in range(7, -1, -1):
            bits.append((b >> shift) & 1)
    return bits


def from_bits(bits: List[int]) -> bytes:
    """Converts a list of bits (MSB first) back to bytes."""
    # Truncate to multiple of 8
    usable_len = (len(bits) // 8) * 8
    res = bytearray()
    for i in range(0, usable_len, 8):
        byte_val = 0
        for b in bits[i:i + 8]:
            byte_val = (byte_val << 1) | (b & 1)
        res.append(byte_val)
    return bytes(res)


def frame_payload(ciphertext_body: bytes) -> bytes:
    """Frames ciphertext body with header:
    - Magic: 'TL' (2 bytes)
    - Version: 1 byte
    - Length: 2 bytes uint16 big-endian
    - CRC-32: 4 bytes uint32 big-endian over body
    - Body: ciphertext bytes
    """
    length = len(ciphertext_body)
    crc = zlib.crc32(ciphertext_body) & 0xFFFFFFFF
    header = struct.pack(">2sBHI", MAGIC, VERSION, length, crc)
    return header + ciphertext_body


def unframe_payload(framed_bytes: bytes) -> bytes:
    """Validates header, verifies CRC-32, and returns extracted ciphertext body."""
    if len(framed_bytes) < 9:
        raise ValueError("Payload too short to contain valid TL header")
    magic, version, length, crc = struct.unpack(">2sBHI", framed_bytes[:9])
    if magic != MAGIC:
        raise ValueError(f"Invalid magic bytes: {magic}. Expected: {MAGIC}")
    body = framed_bytes[9:9 + length]
    if len(body) != length:
        raise ValueError(f"Truncated body: expected {length} bytes, got {len(body)}")
    calc_crc = zlib.crc32(body) & 0xFFFFFFFF
    if calc_crc != crc:
        raise ValueError(f"CRC-32 checksum mismatch: calculated {calc_crc:#x}, header has {crc:#x}")
    return body


def build_payload(
    details: Dict[str, str],
    issuer_privkey: RSAPrivateKey,
    session_key: bytes,
    redundancy: int = DEFAULT_REDUNDANCY
) -> Tuple[bytes, List[int]]:
    """Builds the complete steganographic payload:
    1. Formats student record string.
    2. Signs record with issuer RSA private key.
    3. Bundles record + 2-byte record length + signature.
    4. Encrypts bundle with Geffe stream cipher using session key (prepends 8-byte nonce).
    5. Frames with magic 'TL', version, length, and CRC-32.
    6. Repeats the bit sequence `redundancy` times (default 7x).
    Returns (single_framed_bytes, repeated_bits).
    """
    record_str = record_to_string(details)
    record_bytes = record_str.encode("utf-8")
    sig = sign(record_bytes, issuer_privkey)

    # Pack record length (2 bytes) + record + signature
    bundle = struct.pack(">H", len(record_bytes)) + record_bytes + sig
    ciphertext = encrypt_geffe(bundle, session_key)
    framed = frame_payload(ciphertext)

    single_bits = to_bits(framed)
    repeated_bits = single_bits * redundancy
    return framed, repeated_bits


def majority_vote_bits(repeated_bits: List[int], redundancy: int = DEFAULT_REDUNDANCY) -> List[int]:
    """Applies bitwise majority voting across repeated copies of the payload."""
    total_bits = len(repeated_bits)
    if total_bits % redundancy != 0:
        raise ValueError(f"Bit length {total_bits} is not divisible by redundancy {redundancy}")

    single_len = total_bits // redundancy
    recovered = []
    threshold = redundancy / 2.0

    for i in range(single_len):
        votes = 0
        for r in range(redundancy):
            votes += repeated_bits[r * single_len + i]
        recovered.append(1 if votes > threshold else 0)

    return recovered


def parse_payload(
    payload_bits: List[int],
    session_key: bytes,
    issuer_pubkey: RSAPublicKey,
    redundancy: int = DEFAULT_REDUNDANCY,
    apply_majority_vote: bool = True
) -> Tuple[Dict[str, str], bool]:
    """Recovers and verifies the student record from payload bits:
    1. Majority voting (if redundant).
    2. Header and CRC-32 validation.
    3. Geffe decryption using session key.
    4. RSA signature verification using issuer public key.
    Returns (record_dict, is_signature_valid).
    """
    if apply_majority_vote and len(payload_bits) % redundancy == 0 and len(payload_bits) > (9 * 8 * redundancy):
        single_bits = majority_vote_bits(payload_bits, redundancy=redundancy)
    else:
        single_bits = payload_bits

    framed_bytes = from_bits(single_bits)
    body = unframe_payload(framed_bytes)
    decrypted = decrypt_geffe(body, session_key)

    rec_len = struct.unpack(">H", decrypted[:2])[0]
    rec_bytes = decrypted[2:2 + rec_len]
    sig = decrypted[2 + rec_len:]

    sig_valid = verify(rec_bytes, sig, issuer_pubkey)
    record_dict = string_to_record(rec_bytes.decode("utf-8", errors="replace"))

    return record_dict, sig_valid
