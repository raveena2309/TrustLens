"""tests.py
Simple, comprehensive unit tests verifying all consolidated modules:
- RSA signing, verification, and key wrapping
- Diffie-Hellman session key agreement
- LFSR / Geffe encryption and Berlekamp-Massey attack
- Certificate generation
- Robust DCT ID embedding and extraction
- Fragile LSB embedding, 7x majority voting, and tamper detection
- Laplace Differential Privacy and budget blocking
"""

import io
import unittest
import numpy as np
from PIL import Image

from certificate import generate_certificate
from crypto import (
    rsa_keygen, rsa_sign, rsa_verify, rsa_wrap_key, rsa_unwrap_key,
    dh_generate_keypair, dh_shared_secret,
    LFSR, GeffeGenerator, geffe_encrypt, berlekamp_massey
)
from stego import (
    embed_dct_id, extract_dct_id,
    issue_certificate_full, verify_certificate_full,
    verify_blocks
)
from privacy import laplace_mechanism, exponential_mechanism, PrivacyBudget


class TestTrustLensSimplified(unittest.TestCase):

    def test_rsa_and_dh(self):
        # 1. RSA
        pub, priv = rsa_keygen(bits=512)
        msg = b"Alice|CS101|9.5"
        sig = rsa_sign(msg, priv)
        self.assertTrue(rsa_verify(msg, sig, pub))
        self.assertFalse(rsa_verify(msg + b"!", sig, pub))

        # 2. Key Wrapping
        seed = b"secret_seed_1234"
        wrapped = rsa_wrap_key(seed, pub)
        unwrapped = rsa_unwrap_key(wrapped, priv, out_len=len(seed))
        self.assertEqual(seed, unwrapped)

        # 3. Diffie-Hellman
        a_priv, a_pub = dh_generate_keypair()
        b_priv, b_pub = dh_generate_keypair()
        k_a = dh_shared_secret(a_priv, b_pub)
        k_b = dh_shared_secret(b_priv, a_pub)
        self.assertEqual(k_a, k_b)

    def test_lfsr_geffe_and_berlekamp(self):
        # LFSR
        lfsr = LFSR(size=4, taps=[0, 3], seed=1)
        bits = [lfsr.step() for _ in range(30)]
        self.assertEqual(berlekamp_massey(bits), 4)

        # Geffe
        data = b"Student Certificate Record"
        key = b"session_key_1234"
        encrypted = geffe_encrypt(data, key)
        decrypted = geffe_encrypt(encrypted, key)
        self.assertEqual(data, decrypted)

    def test_dct_robust_id(self):
        img = generate_certificate()
        cert_id = "TL-2026-0123"
        stego = embed_dct_id(img, cert_id, q=20.0)
        extracted = extract_dct_id(stego, q=20.0)
        self.assertEqual(cert_id, extracted)

        # Survives JPEG compression
        buf = io.BytesIO()
        stego.save(buf, "JPEG", quality=80)
        buf.seek(0)
        jpeg_img = Image.open(buf)
        self.assertEqual(extract_dct_id(jpeg_img, q=20.0), cert_id)

    def test_end_to_end_pipeline_and_tampering(self):
        i_pub, i_priv = rsa_keygen(bits=512)
        v_pub, v_priv = rsa_keygen(bits=512)
        session_key = b"session_key_secret_32_bytes_1234"

        details = {
            "name": "Alex Mercer", "roll": "CS-2022-8491",
            "degree": "B.Tech Computer Science", "year": "2026",
            "cgpa": "9.42", "cert_id": "TL-2026-0123"
        }

        # Issue
        cert = issue_certificate_full(details, i_priv, v_pub, session_key)

        # Verify Genuine
        rep_genuine = verify_certificate_full(cert, v_priv, i_pub, session_key)
        self.assertEqual(rep_genuine["verdict"], "GENUINE")
        self.assertEqual(rep_genuine["failed_blocks"], 0)

        # Tamper certificate: paint over CGPA
        arr = np.array(cert)
        arr[840:910, 600:1000, :] = 255  # blank out CGPA
        tampered_img = Image.fromarray(arr)

        rep_forged = verify_certificate_full(tampered_img, v_priv, i_pub, session_key)
        self.assertEqual(rep_forged["verdict"], "FORGED / EDITED")
        self.assertGreater(rep_forged["failed_blocks"], 0)

    def test_privacy_laplace_and_budget(self):
        budget = PrivacyBudget(max_epsilon=3.0)
        self.assertTrue(budget.spend(1.0))
        self.assertTrue(budget.spend(1.5))
        self.assertFalse(budget.spend(1.0))  # Exceeds 3.0 budget!

        noisy = laplace_mechanism(500, epsilon=1.0)
        self.assertGreater(noisy, 400)
        self.assertLess(noisy, 600)


if __name__ == "__main__":
    unittest.main()
