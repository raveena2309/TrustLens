"""Unit tests for BPCS, DCT-QIM with JPEG survival, Spread Spectrum, Reversible, and Public-Key Stego."""

import io
import unittest
import numpy as np
from PIL import Image
from trustlens.certificate import generate_certificate
from trustlens.crypto.rsa_scratch import generate_keypair
from trustlens.stego.bpcs import embed_bpcs, extract_bpcs
from trustlens.stego.dct_qim import embed_dct_id, extract_dct_id
from trustlens.stego.spread import embed_spread_spectrum, extract_spread_spectrum
from trustlens.stego.reversible import embed_reversible, extract_and_restore
from trustlens.stego.pubkey_stego import (
    generate_stego_seed, wrap_stego_seed, unwrap_stego_seed,
    embed_wrapped_seed, extract_wrapped_seed
)


class TestStegoAdvanced(unittest.TestCase):

    def setUp(self):
        self.image = generate_certificate()

    def test_reversible_exact_restoration(self):
        """Checkpoint Step 8: The recovered image is identical to the original (np.array_equal)."""
        payload = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1] * 50
        stego_img, meta = embed_reversible(self.image, payload, channel_idx=1)
        extracted_bits, restored_img = extract_and_restore(stego_img, meta)

        self.assertEqual(payload, extracted_bits)
        orig_arr = np.array(self.image)
        restored_arr = np.array(restored_img)
        self.assertTrue(np.array_equal(orig_arr, restored_arr))

    def test_public_key_stego_wrapping(self):
        """Checkpoint Step 6: Public key wrapped seed recovery."""
        pub, priv = generate_keypair(bits=512)
        seed = generate_stego_seed(byte_length=16)
        wrapped = wrap_stego_seed(seed, pub)

        stego_img = embed_wrapped_seed(self.image, wrapped)
        extracted_wrapped = extract_wrapped_seed(stego_img, byte_length=len(wrapped))
        unwrapped_seed = unwrap_stego_seed(extracted_wrapped, priv)

        self.assertEqual(seed, unwrapped_seed)

    def test_spread_spectrum(self):
        payload = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0]
        stego_img = embed_spread_spectrum(self.image, payload, seed=123, alpha=4.0)
        extracted = extract_spread_spectrum(stego_img, num_bits=len(payload), seed=123)
        self.assertEqual(payload, extracted)

    def test_dct_qim_roundtrip_and_jpeg_survival(self):
        """Checkpoint Step 5: ID survives JPEG compression."""
        cert_id = "TL-2026-0123"
        stego_img = embed_dct_id(self.image, cert_id, q=20.0)

        # Uncompressed check
        extracted_uncompressed = extract_dct_id(stego_img, q=20.0)
        self.assertEqual(extracted_uncompressed, cert_id)

        # JPEG Compression check at Quality 90 and 75
        for quality in (90, 75):
            buf = io.BytesIO()
            stego_img.save(buf, format="JPEG", quality=quality)
            buf.seek(0)
            jpeg_img = Image.open(buf)
            extracted_jpeg = extract_dct_id(jpeg_img, q=20.0)
            self.assertEqual(extracted_jpeg, cert_id, f"Failed at JPEG quality {quality}")


if __name__ == "__main__":
    unittest.main()
