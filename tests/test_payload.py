"""Unit tests for Step 2 payload builder, majority voting, and error resilience."""

import random
import unittest
from trustlens.crypto.rsa_scratch import generate_keypair
from trustlens.stego.payload import (
    build_payload, parse_payload, to_bits, from_bits,
    majority_vote_bits, frame_payload, unframe_payload
)


class TestPayload(unittest.TestCase):

    def setUp(self):
        self.pub, self.priv = generate_keypair(bits=512)
        self.session_key = b"0123456789abcdef0123456789abcdef"
        self.details = {
            "name": "Alex Mercer",
            "roll": "CS-2022-8491",
            "degree": "Bachelor of Technology in Computer Science",
            "year": "2026",
            "cgpa": "9.42"
        }

    def test_bits_roundtrip(self):
        data = b"Testing 123 \x00\xff\xaa\x55 TrustLens"
        bits = to_bits(data)
        recovered = from_bits(bits)
        self.assertEqual(data, recovered)

    def test_frame_unframe(self):
        body = b"Secret ciphertext body data"
        framed = frame_payload(body)
        recovered_body = unframe_payload(framed)
        self.assertEqual(body, recovered_body)

    def test_payload_build_and_parse(self):
        framed, repeated_bits = build_payload(self.details, self.priv, self.session_key, redundancy=7)
        rec, valid = parse_payload(repeated_bits, self.session_key, self.pub, redundancy=7)
        self.assertTrue(valid)
        self.assertEqual(rec["name"], self.details["name"])
        self.assertEqual(rec["cgpa"], self.details["cgpa"])

    def test_5_percent_bit_corruption_resilience(self):
        """Checkpoint: flipping 5% of random bits across the 7 copies still decodes correctly."""
        _, repeated_bits = build_payload(self.details, self.priv, self.session_key, redundancy=7)
        corrupted_bits = list(repeated_bits)

        # Corrupt 5% of total bits randomly
        num_flips = int(0.05 * len(corrupted_bits))
        random.seed(42)
        flip_indices = random.sample(range(len(corrupted_bits)), num_flips)
        for idx in flip_indices:
            corrupted_bits[idx] ^= 1

        rec, valid = parse_payload(corrupted_bits, self.session_key, self.pub, redundancy=7)
        self.assertTrue(valid)
        self.assertEqual(rec["name"], self.details["name"])
        self.assertEqual(rec["cgpa"], self.details["cgpa"])


if __name__ == "__main__":
    unittest.main()
