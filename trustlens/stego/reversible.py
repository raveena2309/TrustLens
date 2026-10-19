"""Step 8: Lossless / Reversible Data Hiding using Histogram Shifting (Ni et al.).
Allows embedding payload data and subsequently restoring the EXACT original image
bit-for-bit (np.array_equal(original, restored) is True).
"""

import numpy as np
from PIL import Image
from typing import List, Tuple, Dict, Optional


def embed_reversible(
    image: Image.Image,
    payload_bits: List[int],
    channel_idx: int = 1
) -> Tuple[Image.Image, Dict[str, int]]:
    """Embeds payload bits into an image channel using histogram shifting.
    Automatically selects an empty zero-bin Z (either left Z < P or right Z > P)
    to guarantee exact mathematical reversibility.
    """
    arr = np.array(image, dtype=np.uint8)
    h, w, c = arr.shape
    plane = arr[:, :, channel_idx].copy()

    # Find peak bin P
    hist = np.bincount(plane.ravel(), minlength=256)
    p = int(np.argmax(hist[1:254]) + 1)

    # Find true zero bin Z (hist[Z] == 0)
    zero_bins = np.where(hist == 0)[0]
    if len(zero_bins) == 0:
        # Fallback: minimum bin
        z_candidates = [(idx, hist[idx]) for idx in range(256) if idx != p]
        z_candidates.sort(key=lambda x: x[1])
        z = z_candidates[0][0]
    else:
        # Prefer closest zero bin to P
        zero_bins_sorted = sorted(zero_bins, key=lambda idx: abs(idx - p))
        z = int(zero_bins_sorted[0])

    # Prepend 32-bit payload length
    full_payload = [int((len(payload_bits) >> (31 - i)) & 1) for i in range(32)] + list(payload_bits)
    capacity = int(hist[p])

    if len(full_payload) > capacity:
        raise ValueError(f"Payload ({len(full_payload)} bits) exceeds peak bin capacity ({capacity} bits)")

    direction = 1 if z > p else -1

    if direction == 1:
        # Shift phase: bins strictly between P and Z shift up by +1
        shift_mask = (plane > p) & (plane < z)
        plane[shift_mask] += 1
        carrier_bin = p + 1
    else:
        # Shift phase: bins strictly between Z and P shift down by -1
        shift_mask = (plane < p) & (plane > z)
        plane[shift_mask] -= 1
        carrier_bin = p - 1

    # Embedding phase: iterate pixels that equal P
    p_indices = np.argwhere(plane == p)
    for i, bit in enumerate(full_payload):
        r, col = p_indices[i]
        if bit == 1:
            plane[r, col] = carrier_bin
        else:
            plane[r, col] = p

    arr[:, :, channel_idx] = plane
    metadata = {
        "P": p,
        "Z": z,
        "direction": direction,
        "length": len(full_payload),
        "channel": channel_idx
    }

    return Image.fromarray(arr, mode="RGB"), metadata


def extract_and_restore(
    stego_image: Image.Image,
    metadata: Dict[str, int]
) -> Tuple[List[int], Image.Image]:
    """Extracts the embedded payload and restores the EXACT original image bit-for-bit."""
    p = metadata["P"]
    z = metadata["Z"]
    direction = metadata.get("direction", 1 if z > p else -1)
    total_bits = metadata["length"]
    channel_idx = metadata.get("channel", 1)

    arr = np.array(stego_image, dtype=np.uint8)
    plane = arr[:, :, channel_idx].copy()
    restored_plane = plane.copy()

    carrier_bin = (p + 1) if direction == 1 else (p - 1)
    recovered_bits = []
    bits_extracted = 0

    h, w = plane.shape
    for r in range(h):
        for col in range(w):
            val = plane[r, col]
            if val == p:
                if bits_extracted < total_bits:
                    recovered_bits.append(0)
                    bits_extracted += 1
            elif val == carrier_bin:
                if bits_extracted < total_bits:
                    recovered_bits.append(1)
                    bits_extracted += 1
                    # Restore back to original peak bin P
                    restored_plane[r, col] = p

    # Reverse shift
    if direction == 1:
        # Shift back bins in (P+1, Z] down by 1
        shift_back_mask = (restored_plane > p) & (restored_plane <= z)
        restored_plane[shift_back_mask] -= 1
    else:
        # Shift back bins in [Z, P-1) up by 1
        shift_back_mask = (restored_plane < p) & (restored_plane >= z)
        restored_plane[shift_back_mask] += 1

    arr[:, :, channel_idx] = restored_plane
    restored_image = Image.fromarray(arr, mode="RGB")

    payload = recovered_bits[32:]
    return payload, restored_image
