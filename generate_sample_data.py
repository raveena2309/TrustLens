"""One-click script to generate sample genuine, tampered, and attacked certificates.
Saves PNG and JPEG test files into samples/ for interactive demonstration in Trust Lab.
"""

import os
from PIL import Image
from trustlens.certificate import generate_certificate
from trustlens.crypto.rsa_scratch import generate_keypair
from trustlens.crypto.dh import create_dh_session
from trustlens.pipeline import issue_certificate
from trustlens.verify.attacks import (
    attack_retype_field, attack_block_tamper, attack_jpeg_compress
)

SAMPLES_DIR = "samples"
os.makedirs(SAMPLES_DIR, exist_ok=True)


def main():
    print("Generating cryptographic keys and session...")
    issuer_pub, issuer_priv = generate_keypair(bits=1024)
    verifier_pub, verifier_priv = generate_keypair(bits=1024)
    _, _, session_key = create_dh_session()

    student_details = {
        "name": "Alex Mercer",
        "roll": "CS-2022-8491",
        "degree": "Bachelor of Technology in Computer Science",
        "year": "2026",
        "cgpa": "9.42",
        "cert_id": "TL-2026-0123"
    }

    print("1. Generating genuine dual-layer certificate...")
    genuine_cert, _, _ = issue_certificate(student_details, issuer_priv, verifier_pub, session_key)
    genuine_path = os.path.join(SAMPLES_DIR, "genuine_certificate.png")
    genuine_cert.save(genuine_path)
    print(f"   Saved: {genuine_path}")

    print("2. Generating forged certificate (Retyped CGPA: 9.98)...")
    forged_cgpa = attack_retype_field(genuine_cert, "cgpa", "9.98")
    forged_cgpa_path = os.path.join(SAMPLES_DIR, "forged_cgpa_certificate.png")
    forged_cgpa.save(forged_cgpa_path)
    print(f"   Saved: {forged_cgpa_path}")

    print("3. Generating forged certificate (Retyped Student Name: Dr. Victor Forger)...")
    forged_name = attack_retype_field(genuine_cert, "name", "Dr. Victor Forger")
    forged_name_path = os.path.join(SAMPLES_DIR, "forged_name_certificate.png")
    forged_name.save(forged_name_path)
    print(f"   Saved: {forged_name_path}")

    print("4. Generating block-tampered certificate (Altered region)...")
    block_tampered = attack_block_tamper(genuine_cert, box=(600, 800, 950, 920))
    block_path = os.path.join(SAMPLES_DIR, "block_tampered_certificate.png")
    block_tampered.save(block_path)
    print(f"   Saved: {block_path}")

    print("5. Generating JPEG compressed damaged certificate (Quality 75)...")
    jpeg_path = os.path.join(SAMPLES_DIR, "damaged_jpeg_quality75.jpg")
    genuine_cert.save(jpeg_path, format="JPEG", quality=75)
    print(f"   Saved: {jpeg_path}")

    print("\n[OK] All sample certificates successfully generated in samples/ directory!")


if __name__ == "__main__":
    main()
