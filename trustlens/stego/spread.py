"""Direct Sequence Spread Spectrum (DSSS) Steganography.
Alternative robust frequency/spatial domain watermark from Module 5:
- Multiplies each bit by a pseudorandom PN sequence (+1 / -1)
- Adds carrier watermark at low gain alpha
- Decodes by matched-filter correlation
"""

import numpy as np
from PIL import Image
from typing import List, Optional


def embed_spread_spectrum(
    image: Image.Image,
    payload_bits: List[int],
    seed: int = 42,
    alpha: float = 2.0
) -> Image.Image:
    """Embeds bits via Direct Sequence Spread Spectrum across image pixels."""
    arr = np.array(image, dtype=np.float32)
    h, w, c = arr.shape
    total_pixels = h * w
    num_bits = len(payload_bits)

    if num_bits == 0:
        return image

    chip_length = total_pixels // num_bits
    if chip_length < 10:
        raise ValueError("Payload too large for spread spectrum embedding")

    rng = np.random.default_rng(seed)
    # Generate pseudo-noise carrier for all chips
    pn_sequence = rng.choice([-1.0, 1.0], size=num_bits * chip_length)

    # Modulate bits onto PN sequence (0 -> -1, 1 -> +1)
    watermark = np.zeros(num_bits * chip_length, dtype=np.float32)
    for i, b in enumerate(payload_bits):
        bit_val = 1.0 if b == 1 else -1.0
        start = i * chip_length
        end = start + chip_length
        watermark[start:end] = bit_val * pn_sequence[start:end] * alpha

    # Add watermark to green channel (channel 1)
    flat_g = arr[:, :, 1].ravel()
    flat_g[:len(watermark)] += watermark
    arr[:, :, 1] = flat_g.reshape((h, w))

    arr_clipped = np.clip(arr, 0, 255).astype(np.uint8)
    return Image.fromarray(arr_clipped, mode="RGB")


def extract_spread_spectrum(
    image: Image.Image,
    num_bits: int,
    seed: int = 42
) -> List[int]:
    """Extracts bits via matched filter correlation with the PN sequence."""
    arr = np.array(image, dtype=np.float32)
    h, w, _ = arr.shape
    total_pixels = h * w
    chip_length = total_pixels // num_bits

    rng = np.random.default_rng(seed)
    pn_sequence = rng.choice([-1.0, 1.0], size=num_bits * chip_length)

    flat_g = arr[:, :, 1].ravel()
    recovered_bits = []

    for i in range(num_bits):
        start = i * chip_length
        end = start + chip_length
        received_chip = flat_g[start:end]
        pn_chip = pn_sequence[start:end]
        # Correlation: dot product
        correlation = np.dot(received_chip, pn_chip)
        recovered_bits.append(1 if correlation > 0 else 0)

    return recovered_bits
