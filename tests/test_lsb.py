"""Unit tests for Step 3 fragile LSB embedding, edge-adaptive ranking, and block tamper localization."""

import unittest
import numpy as np
from PIL import Image
from trustlens.certificate import generate_certificate
from trustlens.stego.lsb import (
    embed_lsb, extract_lsb, verify_block_checksums, BLOCK_SIZE
)
from trustlens.stego.metrics import compute_psnr, compute_ssim


class TestLSB(unittest.TestCase):

    def setUp(self):
        self.image = generate_certificate()
        # Test payload of 4000 bits
        np.random.seed(123)
        self.payload = list(np.random.randint(0, 2, size=4000))
        self.seed = 987654321

    def test_plain_and_edge_adaptive_roundtrip(self):
        stego_img = embed_lsb(self.image, self.payload, stego_seed=self.seed, edge_adaptive=True)
        extracted = extract_lsb(stego_img, stego_seed=self.seed, edge_adaptive=True)
        self.assertEqual(self.payload, extracted)

        # Check PSNR is above 45 dB
        psnr = compute_psnr(self.image, stego_img)
        self.assertGreater(psnr, 45.0)

        # Check SSIM is above 0.99
        ssim = compute_ssim(self.image, stego_img)
        self.assertGreater(ssim, 0.99)

    def test_wrong_seed_gives_garbage(self):
        stego_img = embed_lsb(self.image, self.payload, stego_seed=self.seed, edge_adaptive=True)
        wrong_seed = 111222333
        extracted_wrong = extract_lsb(stego_img, stego_seed=wrong_seed, edge_adaptive=True)
        self.assertNotEqual(self.payload, extracted_wrong)

    def test_single_block_tamper_localization(self):
        """Checkpoint: editing one block flags only that block."""
        stego_img = embed_lsb(self.image, self.payload, stego_seed=self.seed, edge_adaptive=True)
        arr = np.array(stego_img)

        # Tamper exactly one 32x32 block at row 10, col 15
        target_r, target_c = 10, 15
        y0, x0 = target_r * BLOCK_SIZE, target_c * BLOCK_SIZE
        # Invert pixels in upper 7 bit-planes
        arr[y0 + 5:y0 + 25, x0 + 5:x0 + 25, :] ^= 0b00100000

        tampered_img = Image.fromarray(arr)
        tamper_grid = verify_block_checksums(np.array(tampered_img))

        # Check that target_r, target_c is flagged
        self.assertTrue(tamper_grid[target_r, target_c])
        # Check that other blocks remain unflagged
        tamper_count = np.count_nonzero(tamper_grid)
        self.assertEqual(tamper_count, 1)


if __name__ == "__main__":
    unittest.main()
