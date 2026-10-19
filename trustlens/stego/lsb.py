"""Step 3: Fragile LSB Embedding Layer.
Features:
1. Plain sequential LSB embedding
2. Key-seeded pseudo-random position shuffling
3. Edge-adaptive embedding using Sobel filter on upper 7 bit-planes (img >> 1)
4. Block-level 32-bit cryptographic checksums for exact 32x32 pixel tamper localization
"""

import math
import random
import struct
import numpy as np
from PIL import Image
from typing import List, Tuple, Optional, Dict
from ..crypto.hashing import sha256_bytes

BLOCK_SIZE = 32
CHECKSUM_BITS = 32  # 32 bits per 32x32 block


def compute_edge_map_7bit(img_arr: np.ndarray) -> np.ndarray:
    """Computes Sobel edge magnitude map using ONLY the upper 7 bit-planes (img >> 1).
    Since LSB bit modifications do not affect upper 7 bit-planes, the extractor
    derives an identical edge map from the stego image.
    """
    # Shift out the LSB
    upper7 = (img_arr >> 1).astype(np.float32)
    # Convert to grayscale: Y = 0.299 R + 0.587 G + 0.114 B
    gray = 0.299 * upper7[:, :, 0] + 0.587 * upper7[:, :, 1] + 0.114 * upper7[:, :, 2]

    # Sobel kernels
    # Gy = [[-1, -2, -1], [0, 0, 0], [1, 2, 1]]
    # Gx = [[-1, 0, 1], [-2, 0, 2], [-1, 0, 1]]
    # Using scipy/numpy convolution
    pad = np.pad(gray, ((1, 1), (1, 1)), mode='reflect')
    gx = (
        -1 * pad[:-2, :-2] + 1 * pad[:-2, 2:] +
        -2 * pad[1:-1, :-2] + 2 * pad[1:-1, 2:] +
        -1 * pad[2:, :-2] + 1 * pad[2:, 2:]
    )
    gy = (
        -1 * pad[:-2, :-2] - 2 * pad[:-2, 1:-1] - 1 * pad[:-2, 2:] +
         1 * pad[2:, :-2] + 2 * pad[2:, 1:-1] + 1 * pad[2:, 2:]
    )
    mag = np.sqrt(gx * gx + gy * gy)
    return mag


def get_block_checksum_32(block_arr: np.ndarray) -> int:
    """Computes a 32-bit hash over the upper 7 bit-planes of a 32x32x3 image block."""
    upper7 = (block_arr >> 1).astype(np.uint8)
    digest = sha256_bytes(upper7.tobytes())
    return struct.unpack(">I", digest[:4])[0]


def embed_block_checksums(img_arr: np.ndarray) -> np.ndarray:
    """Embeds 32-bit checksums for every 32x32 block into the first 32 pixels of channel 0 (Red)
    within that block's LSBs.
    """
    h, w, c = img_arr.shape
    num_rows = h // BLOCK_SIZE
    num_cols = w // BLOCK_SIZE
    out = img_arr.copy()

    for r in range(num_rows):
        for c_idx in range(num_cols):
            y0 = r * BLOCK_SIZE
            x0 = c_idx * BLOCK_SIZE
            block = out[y0:y0 + BLOCK_SIZE, x0:x0 + BLOCK_SIZE]
            chk = get_block_checksum_32(block)

            # Store 32 bits into the first row of Red channel: (y0, x0 + i, 0)
            for bit_pos in range(32):
                bit = (chk >> (31 - bit_pos)) & 1
                out[y0, x0 + bit_pos, 0] = (out[y0, x0 + bit_pos, 0] & 0xFE) | bit

    return out


def verify_block_checksums(img_arr: np.ndarray) -> np.ndarray:
    """Verifies 32-bit checksums for every 32x32 block.
    Returns a 2D boolean array of shape (num_rows, num_cols)
    where True indicates the block has been tampered with.
    """
    h, w, c = img_arr.shape
    num_rows = h // BLOCK_SIZE
    num_cols = w // BLOCK_SIZE
    tamper_grid = np.zeros((num_rows, num_cols), dtype=bool)

    for r in range(num_rows):
        for c_idx in range(num_cols):
            y0 = r * BLOCK_SIZE
            x0 = c_idx * BLOCK_SIZE
            block = img_arr[y0:y0 + BLOCK_SIZE, x0:x0 + BLOCK_SIZE]

            # Read stored 32-bit checksum from (y0, x0 + i, 0)
            stored_chk = 0
            for bit_pos in range(32):
                bit = int(img_arr[y0, x0 + bit_pos, 0] & 1)
                stored_chk = (stored_chk << 1) | bit

            calc_chk = get_block_checksum_32(block)
            if calc_chk != stored_chk:
                tamper_grid[r, c_idx] = True

    return tamper_grid


def get_available_positions(
    shape: Tuple[int, int, int],
    stego_seed: Optional[int] = None,
    edge_adaptive: bool = True,
    img_for_edges: Optional[np.ndarray] = None,
    max_positions: int = 250000
) -> List[Tuple[int, int, int]]:
    """Builds the list of coordinates (y, x, channel) available for payload bits.
    Excludes:
    - Block checksums: (y0, x0..x0+31, 0) in each 32x32 block.
    - Public key stego seed wrapping: row 0 pixels 0..255.
    Uses vectorized NumPy operations for sub-50ms execution.
    """
    h, w, c = shape
    num_rows = h // BLOCK_SIZE
    num_cols = w // BLOCK_SIZE

    # Create allowed pixel mask
    allowed = np.ones((h, w), dtype=bool)
    # Exclude row 1 for public key stego seed header (up to 2048 bits)
    allowed[1, :min(w, 2048)] = False
    # Exclude block checksums in channel 0
    for r in range(num_rows):
        y0 = r * BLOCK_SIZE
        for c_idx in range(num_cols):
            x0 = c_idx * BLOCK_SIZE
            allowed[y0, x0:x0 + 32] = False

    if edge_adaptive:
        if img_for_edges is None:
            raise ValueError("img_for_edges required for edge_adaptive position selection")
        edge_map = compute_edge_map_7bit(img_for_edges)
        edge_map[~allowed] = -1.0

        if stego_seed is not None:
            # Deterministic seed-based tie breaker
            rng = np.random.default_rng(stego_seed)
            jitter = rng.uniform(0.0, 0.001, size=(h, w))
            scores = edge_map + jitter
            scores[~allowed] = -1.0
        else:
            scores = edge_map

        # Top pixels by edge score
        flat_scores = scores.ravel()
        num_pixels_needed = min(max_positions // 3 + 1000, np.count_nonzero(allowed))
        # Use argpartition for fast top-K retrieval
        part_idx = np.argpartition(-flat_scores, num_pixels_needed)[:num_pixels_needed]
        # Sort only the top-K
        sorted_top = part_idx[np.argsort(-flat_scores[part_idx])]

        positions = []
        for idx in sorted_top:
            y = int(idx // w)
            x = int(idx % w)
            # Embed across channels G, B, R
            for ch in (1, 2, 0):
                positions.append((y, x, ch))
                if len(positions) >= max_positions:
                    return positions
        return positions
    else:
        # Non-edge adaptive: pseudo-random selection
        valid_indices = np.argwhere(allowed)
        if stego_seed is not None:
            rng = np.random.default_rng(stego_seed)
            rng.shuffle(valid_indices)

        positions = []
        for y, x in valid_indices[:max_positions // 3 + 1000]:
            for ch in (1, 2, 0):
                positions.append((int(y), int(x), ch))
                if len(positions) >= max_positions:
                    return positions
        return positions


def embed_lsb(
    image: Image.Image,
    payload_bits: List[int],
    stego_seed: Optional[int] = None,
    edge_adaptive: bool = True,
    include_block_checksums: bool = True
) -> Image.Image:
    """Embeds payload bits into image LSBs using edge-adaptive ordering and block checksums."""
    img_arr = np.array(image, dtype=np.uint8)
    h, w, c = img_arr.shape

    positions = get_available_positions(
        (h, w, c),
        stego_seed=stego_seed,
        edge_adaptive=edge_adaptive,
        img_for_edges=img_arr,
        max_positions=len(payload_bits) + 100
    )

    if len(payload_bits) + 32 > len(positions):
        raise ValueError(f"Payload size ({len(payload_bits)} bits) exceeds available capacity ({len(positions)} bits)")

    # Embed length header: first 32 bits store payload length
    full_bits = [int((len(payload_bits) >> (31 - i)) & 1) for i in range(32)] + list(payload_bits)

    # Embed bits into selected positions using 0xFE mask
    for bit, (y, x, ch) in zip(full_bits, positions):
        img_arr[y, x, ch] = (img_arr[y, x, ch] & 0xFE) | (bit & 1)

    # Finally, compute and embed block checksums over upper 7 bit-planes
    if include_block_checksums:
        img_arr = embed_block_checksums(img_arr)

    return Image.fromarray(img_arr, mode="RGB")


def extract_lsb(
    image: Image.Image,
    stego_seed: Optional[int] = None,
    edge_adaptive: bool = True
) -> List[int]:
    """Extracts payload bits from image LSBs using the identical edge map and seed."""
    img_arr = np.array(image, dtype=np.uint8)
    h, w, c = img_arr.shape

    positions = get_available_positions(
        (h, w, c),
        stego_seed=stego_seed,
        edge_adaptive=edge_adaptive,
        img_for_edges=img_arr,
        max_positions=100000
    )

    # Extract 32-bit length header
    length = 0
    for i in range(32):
        y, x, ch = positions[i]
        bit = int(img_arr[y, x, ch] & 1)
        length = (length << 1) | bit

    if length <= 0 or (32 + length) > len(positions):
        # Invalid length header indicates wrong seed or corrupted image
        return [int(img_arr[y, x, ch] & 1) for y, x, ch in positions[32:32 + 20000]]

    payload_bits = []
    for i in range(32, 32 + length):
        y, x, ch = positions[i]
        payload_bits.append(int(img_arr[y, x, ch] & 1))

    return payload_bits
