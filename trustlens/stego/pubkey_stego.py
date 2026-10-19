"""Step 6: Public-Key Steganography (Module 5).
Wraps the ephemeral certificate stego seed with the verifier's RSA public key using PKCS#1 v1.5,
embedding the wrapped ciphertext into fixed LSB coordinates.
Only the authorized verifier possessing the RSA private key can recover the seed to extract the payload.
"""

import secrets
import numpy as np
from PIL import Image
from typing import Tuple
from ..crypto.rsa_scratch import encrypt_pkcs1, decrypt_pkcs1, RSAPublicKey, RSAPrivateKey


def generate_stego_seed(byte_length: int = 16) -> bytes:
    """Generates a cryptographically secure random stego seed."""
    return secrets.token_bytes(byte_length)


def wrap_stego_seed(seed: bytes, verifier_pubkey: RSAPublicKey) -> bytes:
    """Encrypts stego seed using verifier's RSA public key (EME-PKCS1-v1_5)."""
    return encrypt_pkcs1(seed, verifier_pubkey)


def unwrap_stego_seed(wrapped_bytes: bytes, verifier_privkey: RSAPrivateKey) -> bytes:
    """Decrypts stego seed using verifier's RSA private key."""
    return decrypt_pkcs1(wrapped_bytes, verifier_privkey)


def embed_wrapped_seed(image: Image.Image, wrapped_seed: bytes) -> Image.Image:
    """Embeds wrapped seed bytes into fixed LSB locations:
    row 1, columns 0..(len * 8 - 1), channel 0 (Red).
    (Row 1 avoids the row 0 block checksums).
    """
    arr = np.array(image, dtype=np.uint8)
    h, w, c = arr.shape
    total_bits = len(wrapped_seed) * 8

    if total_bits > w:
        raise ValueError(f"Image width ({w}) insufficient to hold wrapped seed header ({total_bits} bits)")

    bit_idx = 0
    for byte_val in wrapped_seed:
        for shift in range(7, -1, -1):
            bit = (byte_val >> shift) & 1
            arr[1, bit_idx, 0] = (arr[1, bit_idx, 0] & 0xFE) | bit
            bit_idx += 1

    return Image.fromarray(arr, mode="RGB")


def extract_wrapped_seed(image: Image.Image, byte_length: int = 256) -> bytes:
    """Extracts wrapped seed bytes from the fixed LSB locations in row 1, channel 0."""
    arr = np.array(image, dtype=np.uint8)
    h, w, c = arr.shape
    total_bits = byte_length * 8

    if total_bits > w:
        raise ValueError(f"Image width ({w}) smaller than expected seed length ({total_bits} bits)")

    bits = [int(arr[1, i, 0] & 1) for i in range(total_bits)]
    byte_vals = bytearray()
    for i in range(0, total_bits, 8):
        val = 0
        for b in bits[i:i + 8]:
            val = (val << 1) | b
        byte_vals.append(val)

    return bytes(byte_vals)
