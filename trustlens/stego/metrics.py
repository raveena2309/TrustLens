"""Steganography image quality and capacity metrics:
- PSNR (Peak Signal-to-Noise Ratio)
- MSE (Mean Squared Error)
- SSIM (Structural Similarity Index Measure)
- Bit alteration stats and bits-per-pixel (bpp)
"""

import math
import numpy as np
from typing import Dict, Union
from PIL import Image

try:
    from skimage.metrics import structural_similarity as ssim_fn
except ImportError:
    ssim_fn = None


def compute_mse(img1: Union[np.ndarray, Image.Image], img2: Union[np.ndarray, Image.Image]) -> float:
    """Computes Mean Squared Error between two images."""
    arr1 = np.asarray(img1, dtype=np.float64)
    arr2 = np.asarray(img2, dtype=np.float64)
    if arr1.shape != arr2.shape:
        raise ValueError(f"Image shapes do not match: {arr1.shape} vs {arr2.shape}")
    return float(np.mean((arr1 - arr2) ** 2))


def compute_psnr(img1: Union[np.ndarray, Image.Image], img2: Union[np.ndarray, Image.Image]) -> float:
    """Computes Peak Signal-to-Noise Ratio (dB) between two images.
    Returns 100.0 dB if images are identical.
    """
    mse = compute_mse(img1, img2)
    if mse == 0.0:
        return 100.0  # Identical images
    return float(10.0 * math.log10((255.0 ** 2) / mse))


def compute_ssim(img1: Union[np.ndarray, Image.Image], img2: Union[np.ndarray, Image.Image]) -> float:
    """Computes Structural Similarity Index (SSIM)."""
    arr1 = np.asarray(img1)
    arr2 = np.asarray(img2)
    if ssim_fn is not None:
        if arr1.ndim == 3:
            return float(ssim_fn(arr1, arr2, channel_axis=2, data_range=255))
        return float(ssim_fn(arr1, arr2, data_range=255))

    # Fallback SSIM approximation if skimage unavailable
    c1 = (0.01 * 255) ** 2
    c2 = (0.03 * 255) ** 2
    mu1 = np.mean(arr1)
    mu2 = np.mean(arr2)
    var1 = np.var(arr1)
    var2 = np.var(arr2)
    cov = np.mean((arr1 - mu1) * (arr2 - mu2))
    ssim_val = ((2 * mu1 * mu2 + c1) * (2 * cov + c2)) / ((mu1**2 + mu2**2 + c1) * (var1 + var2 + c2))
    return float(ssim_val)


def compute_metrics(original: Union[np.ndarray, Image.Image], stego: Union[np.ndarray, Image.Image], payload_bits: int = 0) -> Dict[str, float]:
    """Computes a full suite of steganographic evaluation metrics."""
    arr_orig = np.asarray(original, dtype=np.uint8)
    arr_stego = np.asarray(stego, dtype=np.uint8)

    mse = compute_mse(arr_orig, arr_stego)
    psnr = compute_psnr(arr_orig, arr_stego)
    ssim_val = compute_ssim(arr_orig, arr_stego)

    diff_pixels = np.count_nonzero(arr_orig != arr_stego)
    total_pixels = arr_orig.size
    bpp = (payload_bits / (arr_orig.shape[0] * arr_orig.shape[1])) if payload_bits > 0 else 0.0

    return {
        "psnr_db": round(psnr, 2),
        "ssim": round(ssim_val, 4),
        "mse": round(mse, 4),
        "pixels_modified": int(diff_pixels),
        "pixels_modified_pct": round((diff_pixels / total_pixels) * 100.0, 3),
        "bpp": round(bpp, 4)
    }
