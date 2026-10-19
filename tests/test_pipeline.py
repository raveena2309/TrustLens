"""Unit tests for Step 6 & 7 integrated pipeline and attack scenarios."""

import unittest
import numpy as np
from PIL import Image
from trustlens.crypto.rsa_scratch import generate_keypair
from trustlens.crypto.dh import create_dh_session
from trustlens.pipeline import issue_certificate, verify_certificate
from trustlens.verify.verdict import Verdict
from trustlens.verify.attacks import (
    attack_retype_field, attack_jpeg_compress, attack_block_tamper
)


class TestPipeline(unittest.TestCase):

    def setUp(self):
        # 512-bit keys for fast unit tests
        self.issuer_pub, self.issuer_priv = generate_keypair(bits=512)
        self.verifier_pub, self.verifier_priv = generate_keypair(bits=512)
        _, _, self.session_key = create_dh_session()

        self.details = {
            "name": "Alex Mercer",
            "roll": "CS-2022-8491",
            "degree": "Bachelor of Technology in Computer Science",
            "year": "2026",
            "cgpa": "9.42",
            "cert_id": "TL-2026-0123"
        }

    def test_genuine_certificate(self):
        cert, _, _ = issue_certificate(
            self.details,
            self.issuer_priv,
            self.verifier_pub,
            self.session_key
        )

        report = verify_certificate(
            cert,
            self.verifier_priv,
            self.issuer_pub,
            self.session_key,
            expected_details=self.details
        )

        self.assertEqual(report.verdict, Verdict.GENUINE)
        self.assertTrue(report.signature_valid)
        self.assertEqual(report.tamper_stats["failed_blocks"], 0)
        self.assertEqual(report.dct_id, "TL-2026-0123")

    def test_retyped_field_forgery(self):
        cert, _, _ = issue_certificate(
            self.details,
            self.issuer_priv,
            self.verifier_pub,
            self.session_key
        )

        # Attacker tampers CGPA to 9.99
        forged = attack_retype_field(cert, "cgpa", "9.99")

        report = verify_certificate(
            forged,
            self.verifier_priv,
            self.issuer_pub,
            self.session_key,
            expected_details=self.details
        )

        self.assertEqual(report.verdict, Verdict.FORGED_EDITED)
        self.assertGreater(report.tamper_stats["failed_blocks"], 0)

    def test_jpeg_compression_damaged_original(self):
        cert, _, _ = issue_certificate(
            self.details,
            self.issuer_priv,
            self.verifier_pub,
            self.session_key
        )

        # JPEG compression destroys LSB fragile layer
        compressed = attack_jpeg_compress(cert, quality=75)

        report = verify_certificate(
            compressed,
            self.verifier_priv,
            self.issuer_pub,
            self.session_key,
            expected_details=self.details
        )

        self.assertEqual(report.verdict, Verdict.DAMAGED_ORIGINAL)
        self.assertEqual(report.dct_id, "TL-2026-0123")

    def test_unrelated_random_image(self):
        random_img = Image.fromarray(np.random.randint(0, 255, (1152, 1600, 3), dtype=np.uint8))

        report = verify_certificate(
            random_img,
            self.verifier_priv,
            self.issuer_pub,
            self.session_key
        )

        self.assertEqual(report.verdict, Verdict.NOT_TRUSTLENS)


if __name__ == "__main__":
    unittest.main()
