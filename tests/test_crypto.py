"""Comprehensive Unit Tests for Crypto Module (Module 4 syllabus)."""

import unittest
from trustlens.crypto.hashing import sha256_bytes, sha256_hex, sha256_scratch
from trustlens.crypto.rsa_scratch import (
    generate_keypair, sign, verify, encrypt_pkcs1, decrypt_pkcs1
)
from trustlens.crypto.dh import DiffieHellman, create_dh_session, DH_DEMO_P, DH_DEMO_G
from trustlens.crypto.lfsr import (
    LFSR, GeffeGenerator, berlekamp_massey, encrypt_geffe, decrypt_geffe
)
from trustlens.crypto.classical import (
    caesar_encrypt, caesar_decrypt, caesar_break,
    beaufort_encrypt, beaufort_decrypt,
    columnar_encrypt, columnar_decrypt
)
from trustlens.crypto.classical_more import (
    monoalphabetic_encrypt, monoalphabetic_decrypt, monoalphabetic_break,
    generate_monoalphabetic_key,
    homophonic_encrypt, homophonic_decrypt, homophonic_frequency_analysis,
    polyphonic_encrypt, polyphonic_decrypt,
    CardanGrille,
    to_cycles, from_cycles
)
from trustlens.crypto.cellular import (
    Rule30Keystream, compare_stream_generators
)


class TestCryptoModule(unittest.TestCase):

    def test_sha256(self):
        msg = b"TrustLens+"
        fast_hash = sha256_bytes(msg, use_scratch=False)
        scratch_hash = sha256_bytes(msg, use_scratch=True)
        self.assertEqual(fast_hash, scratch_hash)
        self.assertEqual(len(fast_hash), 32)

    def test_rsa_scratch_sign_verify(self):
        # Test with 512 bits for speed during unit tests
        pub, priv = generate_keypair(bits=512)
        message = b"Alice|CS101|B.Tech|2026|9.45"
        sig = sign(message, priv)
        self.assertTrue(verify(message, sig, pub))
        # Tampered message must fail
        self.assertFalse(verify(message + b"!", sig, pub))

    def test_rsa_scratch_encrypt_decrypt(self):
        pub, priv = generate_keypair(bits=512)
        secret = b"random_stego_seed_12345"
        cipher = encrypt_pkcs1(secret, pub)
        recovered = decrypt_pkcs1(cipher, priv)
        self.assertEqual(secret, recovered)

    def test_diffie_hellman(self):
        # Demo parameters
        dh1 = DiffieHellman(p=DH_DEMO_P, g=DH_DEMO_G)
        dh2 = DiffieHellman(p=DH_DEMO_P, g=DH_DEMO_G)
        k1 = dh1.derive_key(dh2.public_key)
        k2 = dh2.derive_key(dh1.public_key)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 32)

        # RFC standard exchange
        _, _, session_key = create_dh_session()
        self.assertEqual(len(session_key), 32)

    def test_lfsr_and_berlekamp_massey(self):
        # 4-bit LFSR with known polynomial x^4 + x + 1 (taps [0, 3])
        lfsr = LFSR(size=4, taps=[0, 3], initial_state=1)
        bits = lfsr.generate_bits(30)
        # Period should be 2^4 - 1 = 15
        self.assertEqual(bits[:15], bits[15:30])

        # Berlekamp-Massey should determine linear complexity is 4
        lc, poly = berlekamp_massey(bits)
        self.assertEqual(lc, 4)

    def test_geffe_encrypt_decrypt(self):
        key = b"0123456789abcdef0123456789abcdef"
        data = b"Student Certificate Payload Data 2026"
        encrypted = encrypt_geffe(data, key)
        # Check nonce prepended
        self.assertGreater(len(encrypted), len(data))
        decrypted = decrypt_geffe(encrypted, key)
        self.assertEqual(data, decrypted)

    def test_caesar(self):
        text = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        enc = caesar_encrypt(text, 7)
        dec = caesar_decrypt(enc, 7)
        self.assertEqual(text, dec)

        best_shift, broken_text, _ = caesar_break(enc)
        self.assertEqual(best_shift, 7)
        self.assertEqual(broken_text, text)

    def test_beaufort(self):
        text = "DEFENDTHEEASTWALLOFTHECASTLE"
        key = "FORTIFICATION"
        enc = beaufort_encrypt(text, key)
        # Reciprocal cipher: decrypt is identical to encrypt
        dec = beaufort_decrypt(enc, key)
        self.assertEqual(text, dec)

    def test_columnar(self):
        text = "ATTACKATDAWN"
        key = "ZEBRA"
        enc = columnar_encrypt(text, key)
        dec = columnar_decrypt(enc, key)
        self.assertTrue(dec.startswith(text))

    def test_monoalphabetic(self):
        key = generate_monoalphabetic_key()
        text = "EXPERIENCE IS THE TEACHER OF ALL THINGS"
        enc = monoalphabetic_encrypt(text, key)
        dec = monoalphabetic_decrypt(enc, key)
        self.assertEqual(text, dec)

    def test_homophonic(self):
        text = "TRUSTLENSPROTECTEDCERTIFICATE"
        enc = homophonic_encrypt(text)
        dec = homophonic_decrypt(enc)
        self.assertEqual(text, dec)

        freq = homophonic_frequency_analysis(enc)
        # Check no single symbol monopolizes the frequency like 'E' would in monoalphabetic
        max_freq = max(freq.values())
        self.assertLess(max_freq, 15.0)

    def test_polyphonic(self):
        text = "TRUST"
        enc = polyphonic_encrypt(text)
        resolved, _ = polyphonic_decrypt(enc)
        self.assertEqual(resolved, "TRUST")

    def test_cardan_grille(self):
        grille = CardanGrille(size=6)
        text = "SECRETTRUSTLENSUNIVERSITYDEGREECERT!"
        enc = grille.encrypt(text)
        dec = grille.decrypt(enc)
        self.assertEqual(dec[:len(text)], text)

    def test_cyclic_notation(self):
        perm = [1, 2, 0, 4, 3]  # (0 1 2)(3 4)
        cycle_str = to_cycles(perm, one_indexed=False)
        self.assertIn("(0 1 2)", cycle_str)
        self.assertIn("(3 4)", cycle_str)

        recovered = from_cycles(cycle_str, length=5, one_indexed=False)
        self.assertEqual(perm, recovered)

    def test_cellular_automata_rule30(self):
        seed = b"RULE30_SECRET_KEY_1234567890"
        ca = Rule30Keystream(seed, width=63)
        bits = ca.generate_bits(64)
        self.assertEqual(len(bits), 64)

        comparison = compare_stream_generators(seed, num_bits=64)
        self.assertTrue(comparison["LFSR_19"]["broken_easily"])
        self.assertFalse(comparison["Rule30_CA"]["broken_easily"])
        self.assertFalse(comparison["Geffe"]["broken_easily"])


if __name__ == "__main__":
    unittest.main()
