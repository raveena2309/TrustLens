"""Steganography package for TrustLens+ covering Module 5 of syllabus:
- LSB: Fragile, key-seeded, edge-adaptive embedding with 32x32 block tamper detection
- BPCS: Bit-Plane Complexity Segmentation in Canonical Gray Code space
- DCT QIM: Robust transform-domain watermarking surviving JPEG compression
- Spread Spectrum: Direct sequence PN carrier watermarking
- Reversible: Histogram shifting lossless data hiding
- Public-Key Steganography: RSA-wrapped stego seeds
- Metrics: PSNR, SSIM, MSE, BPP
"""

from .metrics import compute_psnr, compute_ssim, compute_mse, compute_metrics
from .payload import (
    build_payload, parse_payload, to_bits, from_bits,
    majority_vote_bits, frame_payload, unframe_payload,
    record_to_string, string_to_record
)
from .lsb import (
    embed_lsb, extract_lsb, embed_block_checksums, verify_block_checksums,
    compute_edge_map_7bit, BLOCK_SIZE
)
from .bpcs import (
    embed_bpcs, extract_bpcs, compute_complexity,
    binary_to_gray, gray_to_binary
)
from .dct_qim import (
    embed_dct_id, extract_dct_id, cert_id_to_bits, bits_to_cert_id,
    qim_embed_coeff, qim_extract_coeff
)
from .spread import embed_spread_spectrum, extract_spread_spectrum
from .reversible import embed_reversible, extract_and_restore
from .pubkey_stego import (
    generate_stego_seed, wrap_stego_seed, unwrap_stego_seed,
    embed_wrapped_seed, extract_wrapped_seed
)
