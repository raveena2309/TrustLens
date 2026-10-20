"""generate_sample_data.py
One-click script to generate sample genuine, tampered, and damaged certificates
in the samples/ folder for instant testing in TrustLens.
"""

import os
import numpy as np
from PIL import Image, ImageDraw

from certificate import generate_certificate
from crypto import rsa_keygen, dh_generate_keypair, dh_shared_secret
from stego import issue_certificate_full

os.makedirs("samples", exist_ok=True)


def main():
    print("Generating keys...")
    i_pub, i_priv = rsa_keygen(bits=1024)
    v_pub, v_priv = rsa_keygen(bits=1024)
    a_priv, a_pub = dh_generate_keypair()
    b_priv, b_pub = dh_generate_keypair()
    session_key = dh_shared_secret(a_priv, b_pub)

    details = {
        "name": "Alex Mercer", "roll": "CS-2022-8491",
        "degree": "Bachelor of Technology in Computer Science",
        "year": "2026", "cgpa": "9.42", "cert_id": "TL-2026-0123"
    }

    print("1. Generating genuine certificate...")
    genuine = issue_certificate_full(details, i_priv, v_pub, session_key)
    genuine.save("samples/genuine_certificate.png")
    print("   Saved: samples/genuine_certificate.png")

    print("2. Generating forged certificate (Retyped CGPA 9.98)...")
    forged = genuine.copy()
    d = ImageDraw.Draw(forged)
    d.rectangle([600, 840, 1000, 910], fill=(250, 248, 240))
    d.text((800, 875), "Cumulative Grade Point Average (CGPA): 9.98 / 10.0", fill=(128, 20, 20), anchor="mm")
    forged.save("samples/forged_cgpa_certificate.png")
    print("   Saved: samples/forged_cgpa_certificate.png")

    print("3. Generating damaged original certificate (JPEG Q=75)...")
    genuine.save("samples/damaged_jpeg_quality75.jpg", "JPEG", quality=75)
    print("   Saved: samples/damaged_jpeg_quality75.jpg")

    print("\n[OK] Sample certificates ready in samples/ directory!")


if __name__ == "__main__":
    main()
