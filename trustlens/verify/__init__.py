"""Verification and attack simulation module for TrustLens+:
- OCR: field reading with clean label stripping
- Tamper: 32x32 block integrity verification and heatmap visualizer
- Verdict: categorical state machine and fuzzy/exact field comparison
- Attacks: realistic forgery simulator
"""

from .ocr import ocr_field, ocr_all_fields, clean_field_text, preprocess_for_ocr
from .tamper import generate_tamper_map, create_tamper_heatmap
from .verdict import Verdict, compare_fields, evaluate_verdict
from .attacks import (
    attack_retype_field,
    attack_block_tamper,
    attack_jpeg_compress,
    attack_resize,
    attack_crop,
    attack_splice,
    attack_transplant_lsb
)
