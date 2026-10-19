"""Step 7: Certificate Verdict Engine and Field Comparison.
Compares OCR-extracted printed text against digitally signed payload records,
analyzes fragile block tamper maps and robust DCT identity layers,
and outputs categorical verdicts according to the specification table.
"""

import difflib
from enum import Enum
from typing import Dict, Any, Optional, Tuple


class Verdict(str, Enum):
    GENUINE = "GENUINE"
    FORGED_EDITED = "FORGED / EDITED"
    DAMAGED_ORIGINAL = "DAMAGED ORIGINAL"
    NOT_TRUSTLENS = "NOT A TRUSTLENS CERTIFICATE"


def compare_fields(printed_fields: Dict[str, str], hidden_record: Dict[str, str]) -> Dict[str, Any]:
    """Compares printed OCR fields against decrypted hidden record:
    - Name and Degree: Fuzzy match (difflib SequenceMatcher ratio >= 0.90)
    - Roll, Year, CGPA: Exact match (critical identifiers)
    """
    field_results = {}
    all_matched = True

    for field in ["name", "roll", "degree", "year", "cgpa"]:
        p_val = printed_fields.get(field, "").strip()
        h_val = hidden_record.get(field, "").strip()

        if field in ("name", "degree"):
            # Fuzzy match
            ratio = difflib.SequenceMatcher(None, p_val.lower(), h_val.lower()).ratio()
            matched = (ratio >= 0.90)
            field_results[field] = {
                "printed": p_val,
                "hidden": h_val,
                "match": matched,
                "match_type": "fuzzy",
                "similarity": round(ratio, 3)
            }
        else:
            # Exact match for digits and identifiers
            matched = (p_val == h_val) and (p_val != "")
            field_results[field] = {
                "printed": p_val,
                "hidden": h_val,
                "match": matched,
                "match_type": "exact",
                "similarity": 1.0 if matched else 0.0
            }

        if not matched:
            all_matched = False

    return {
        "fields": field_results,
        "all_fields_matched": all_matched
    }


def evaluate_verdict(
    has_header: bool,
    signature_valid: bool,
    fields_match: bool,
    tamper_stats: Dict[str, Any],
    dct_id: Optional[str] = None
) -> Tuple[Verdict, str, Dict[str, Any]]:
    """Evaluates comprehensive verification state and returns (verdict, reason, details):
    1. Header found, signature valid, all fields match, no failed blocks -> GENUINE
    2. Signature valid but fields mismatch, or blocks fail -> FORGED / EDITED
    3. Signature fails or payload corrupted -> FORGED
    4. Fragile layer destroyed (no header/corrupted) but DCT ID readable -> DAMAGED ORIGINAL
    5. No header found and no DCT ID -> NOT A TRUSTLENS CERTIFICATE
    """
    failed_blocks = tamper_stats.get("failed_blocks", 0)

    # Condition 1: Genuine
    if has_header and signature_valid and fields_match and (failed_blocks == 0):
        verdict = Verdict.GENUINE
        reason = "Cryptographic signature is valid, all printed fields match hidden record, and all 32x32 image blocks are intact."

    # Condition 2: Edited / Forged with valid or invalid signature
    elif has_header and signature_valid and (not fields_match or failed_blocks > 0):
        verdict = Verdict.FORGED_EDITED
        reasons = []
        if not fields_match:
            reasons.append("printed field text differs from digitally signed hidden record")
        if failed_blocks > 0:
            reasons.append(f"{failed_blocks} image blocks failed tamper integrity checksums")
        reason = "Tampering detected: " + " and ".join(reasons) + "."

    # Condition 3: Signature invalid or payload corrupted
    elif has_header and not signature_valid:
        verdict = Verdict.FORGED_EDITED
        reason = "Digital signature verification failed: payload has been altered or forged."

    # Condition 4: Fragile layer destroyed, but robust DCT ID recovered
    elif (not has_header or not signature_valid) and (dct_id is not None):
        verdict = Verdict.DAMAGED_ORIGINAL
        reason = f"Fragile LSB layer destroyed (likely due to recompression or resizing), but robust DCT layer recovered Certificate ID: {dct_id}."

    # Condition 5: Not TrustLens
    else:
        verdict = Verdict.NOT_TRUSTLENS
        reason = "No TrustLens steganographic header or robust DCT watermark could be identified."

    details = {
        "verdict": verdict.value,
        "reason": reason,
        "has_header": has_header,
        "signature_valid": signature_valid,
        "fields_match": fields_match,
        "failed_blocks": failed_blocks,
        "dct_id": dct_id
    }

    return verdict, reason, details
