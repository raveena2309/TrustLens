"""Step 6 & 7: Integrated Certificate Issuance and Verification Pipeline.
Orchestrates dual-layer steganography:
- Robust DCT layer for Certificate ID
- Fragile LSB layer with edge-adaptive positioning and 32x32 block tamper detection
- RSA digital signature of academic records
- Geffe stream encryption with Diffie-Hellman derived session key
- Public-Key Steganography for verifier-only seed unwrapping
- OCR field extraction and categorical verdict generation
"""

import numpy as np
from PIL import Image
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass

from .certificate import generate_certificate
from .crypto.rsa_scratch import (
    RSAPublicKey, RSAPrivateKey, generate_keypair
)
from .crypto.dh import create_dh_session
from .stego.dct_qim import embed_dct_id, extract_dct_id
from .stego.payload import build_payload, parse_payload
from .stego.lsb import embed_lsb, extract_lsb
from .stego.pubkey_stego import (
    generate_stego_seed, wrap_stego_seed, unwrap_stego_seed,
    embed_wrapped_seed, extract_wrapped_seed
)
from .verify.ocr import ocr_all_fields
from .verify.tamper import generate_tamper_map, create_tamper_heatmap
from .verify.verdict import Verdict, compare_fields, evaluate_verdict


@dataclass
class VerificationReport:
    verdict: Verdict
    reason: str
    is_genuine: bool
    hidden_record: Optional[Dict[str, str]]
    printed_fields: Dict[str, str]
    field_comparison: Optional[Dict[str, Any]]
    signature_valid: bool
    tamper_stats: Dict[str, Any]
    tamper_grid: np.ndarray
    heatmap_image: Image.Image
    dct_id: Optional[str]
    has_header: bool


def issue_certificate(
    details: Dict[str, str],
    issuer_privkey: RSAPrivateKey,
    verifier_pubkey: RSAPublicKey,
    session_key: bytes,
    redundancy: int = 7,
    dct_q: float = 20.0
) -> Tuple[Image.Image, bytes, int]:
    """Issues a dual-layer TrustLens+ certificate:
    1. Renders certificate base image with academic styling.
    2. Embeds robust DCT layer carrying Certificate ID.
    3. Builds signed, Geffe-encrypted payload with 7x majority voting redundancy.
    4. Generates random stego seed and wraps it with verifier's RSA public key.
    5. Embeds fragile LSB payload using edge-adaptive ordering + 32x32 block checksums.
    6. Embeds RSA-wrapped stego seed at designated header coordinates.
    Returns (stego_certificate_image, stego_seed_bytes, seed_int).
    """
    # 1. Render base certificate
    cert_img = generate_certificate(details)

    # 2. Embed robust DCT layer FIRST
    cert_id = details.get("cert_id", "TL-2026-0123")
    img_dct = embed_dct_id(cert_img, cert_id, q=dct_q)

    # 3. Generate stego seed and wrap with verifier's RSA public key
    stego_seed_bytes = generate_stego_seed(byte_length=16)
    wrapped_seed = wrap_stego_seed(stego_seed_bytes, verifier_pubkey)
    seed_int = int.from_bytes(stego_seed_bytes[:8], "big")

    # 4. Build payload: record + RSA sign + Geffe encrypt + CRC-32 + 7x redundancy
    _, repeated_bits = build_payload(
        details,
        issuer_privkey,
        session_key,
        redundancy=redundancy
    )

    # 5. Embed wrapped seed into reserved header LSB positions (row 1)
    img_with_seed = embed_wrapped_seed(img_dct, wrapped_seed)

    # 6. Embed fragile LSB payload and compute block checksums over entire image
    final_stego_image = embed_lsb(
        img_with_seed,
        repeated_bits,
        stego_seed=seed_int,
        edge_adaptive=True,
        include_block_checksums=True
    )

    return final_stego_image, stego_seed_bytes, seed_int


def verify_certificate(
    image: Image.Image,
    verifier_privkey: RSAPrivateKey,
    issuer_pubkey: RSAPublicKey,
    session_key: bytes,
    redundancy: int = 7,
    dct_q: float = 20.0,
    expected_details: Optional[Dict[str, str]] = None
) -> VerificationReport:
    """Verifies a certificate end-to-end:
    1. Extracts robust DCT Certificate ID.
    2. Unwraps stego seed using verifier's RSA private key.
    3. Extracts and majority-votes LSB payload, decrypts Geffe, and checks RSA signature.
    4. Computes 32x32 block tamper map and generates visual heatmap.
    5. Runs OCR on printed fields and compares against hidden record.
    6. Synthesizes overall categorical verdict.
    """
    # 1. Extract robust DCT ID
    dct_id = extract_dct_id(image, q=dct_q)

    # 2. Extract wrapped seed and unwrap with verifier private key
    has_header = False
    signature_valid = False
    hidden_record = None
    seed_int = None

    key_bytes = verifier_privkey.byte_length
    try:
        wrapped_seed = extract_wrapped_seed(image, byte_length=key_bytes)
        stego_seed_bytes = unwrap_stego_seed(wrapped_seed, verifier_privkey)
        seed_int = int.from_bytes(stego_seed_bytes[:8], "big")

        # 3. Extract LSB payload using recovered seed
        payload_bits = extract_lsb(image, stego_seed=seed_int, edge_adaptive=True)
        hidden_record, signature_valid = parse_payload(
            payload_bits,
            session_key,
            issuer_pubkey,
            redundancy=redundancy
        )
        has_header = True
    except Exception:
        has_header = False
        signature_valid = False
        hidden_record = None

    # 4. Tamper map & heatmap
    tamper_grid, tamper_stats = generate_tamper_map(image)
    heatmap_img = create_tamper_heatmap(image, tamper_grid)

    # 5. OCR field extraction
    fallback_defaults = hidden_record or expected_details
    printed_fields = ocr_all_fields(image, fallback_defaults=fallback_defaults)

    # 6. Field comparison
    if hidden_record is not None:
        field_comp = compare_fields(printed_fields, hidden_record)
        fields_match = field_comp["all_fields_matched"]
    else:
        field_comp = None
        fields_match = False

    # 7. Verdict evaluation
    verdict, reason, _ = evaluate_verdict(
        has_header=has_header,
        signature_valid=signature_valid,
        fields_match=fields_match,
        tamper_stats=tamper_stats,
        dct_id=dct_id
    )

    return VerificationReport(
        verdict=verdict,
        reason=reason,
        is_genuine=(verdict == Verdict.GENUINE),
        hidden_record=hidden_record,
        printed_fields=printed_fields,
        field_comparison=field_comp,
        signature_valid=signature_valid,
        tamper_stats=tamper_stats,
        tamper_grid=tamper_grid,
        heatmap_image=heatmap_img,
        dct_id=dct_id,
        has_header=has_header
    )
