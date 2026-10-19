"""Cellular Automata (Rule 30) Keystream Generator and Stream Comparison.
Implements Wolfram's Rule 30 1D cellular automaton for pseudorandom bit generation,
and compares its cryptographic metrics (linear complexity via Berlekamp-Massey and bit balance)
against LFSR and Geffe generators under Module 4.
"""

from typing import List, Dict, Any
from .lfsr import LFSR, GeffeGenerator, berlekamp_massey


class Rule30Keystream:
    """Wolfram Rule 30 Keystream Generator.
    Local rule: new_state = left XOR (center OR right).
    Center column over time serves as the output pseudorandom keystream bit.
    """

    def __init__(self, seed: bytes, width: int = 127):
        if width % 2 == 0:
            width += 1  # Force odd width for a well-defined center cell
        self.width = width
        self.center_idx = width // 2

        # Convert seed bytes into binary array
        seed_bits = []
        for b in seed:
            for shift in range(7, -1, -1):
                seed_bits.append((b >> shift) & 1)

        # Pad or trim seed_bits to match register width
        if len(seed_bits) < self.width:
            seed_bits = seed_bits * (self.width // len(seed_bits) + 1)
        self.state = seed_bits[:self.width]

        # Ensure state is not all zeros
        if sum(self.state) == 0:
            self.state[self.center_idx] = 1

    def step(self) -> int:
        """Executes one Rule 30 time step and returns the center cell bit."""
        out_bit = self.state[self.center_idx]
        w = self.width
        new_state = [0] * w

        for i in range(w):
            left = self.state[(i - 1) % w]
            center = self.state[i]
            right = self.state[(i + 1) % w]
            # Rule 30 formula: left XOR (center OR right)
            new_state[i] = left ^ (center | right)

        self.state = new_state
        return out_bit

    def generate_bits(self, count: int) -> List[int]:
        return [self.step() for _ in range(count)]

    def generate_bytes(self, length: int) -> bytes:
        res = bytearray(length)
        for i in range(length):
            byte_val = 0
            for _ in range(8):
                byte_val = (byte_val << 1) | self.step()
            res[i] = byte_val
        return bytes(res)


def compute_bit_balance(bits: List[int]) -> Dict[str, float]:
    """Computes 0/1 bit balance and Chi-square test statistic against ideal uniform distribution."""
    n = len(bits)
    if n == 0:
        return {"ones": 0, "zeros": 0, "ones_pct": 0.0, "chi_sq": 0.0}

    ones = sum(bits)
    zeros = n - ones
    expected = n / 2.0
    chi_sq = ((zeros - expected) ** 2 / expected) + ((ones - expected) ** 2 / expected)

    return {
        "n": n,
        "ones": ones,
        "zeros": zeros,
        "ones_pct": (ones / n) * 100.0,
        "chi_sq": round(chi_sq, 4)
    }


def compare_stream_generators(seed: bytes, num_bits: int = 128) -> Dict[str, Any]:
    """Compares LFSR (19-bit), Geffe generator, and Rule 30 CA:
    1. Linear complexity L via Berlekamp-Massey
    2. Bit balance (percentage of ones)
    3. Chi-square randomness statistic
    """
    # 1. Single LFSR (Degree 19)
    seed_int = int.from_bytes(seed[:4], "big") | 1
    single_lfsr = LFSR(size=19, taps=[0, 1, 4, 18], initial_state=seed_int)
    lfsr_bits = single_lfsr.generate_bits(num_bits)
    lfsr_lc, _ = berlekamp_massey(lfsr_bits)
    lfsr_bal = compute_bit_balance(lfsr_bits)

    # 2. Geffe Generator
    geffe = GeffeGenerator(seed)
    geffe_bits = [geffe.step() for _ in range(num_bits)]
    geffe_lc, _ = berlekamp_massey(geffe_bits)
    geffe_bal = compute_bit_balance(geffe_bits)

    # 3. Rule 30 Cellular Automaton
    ca = Rule30Keystream(seed)
    ca_bits = ca.generate_bits(num_bits)
    ca_lc, _ = berlekamp_massey(ca_bits)
    ca_bal = compute_bit_balance(ca_bits)

    return {
        "LFSR_19": {
            "bits_tested": num_bits,
            "linear_complexity": lfsr_lc,
            "expected_lc_bound": 19,
            "bit_balance": lfsr_bal,
            "broken_easily": (lfsr_lc <= 19)
        },
        "Geffe": {
            "bits_tested": num_bits,
            "linear_complexity": geffe_lc,
            "bit_balance": geffe_bal,
            "broken_easily": False
        },
        "Rule30_CA": {
            "bits_tested": num_bits,
            "linear_complexity": ca_lc,
            "bit_balance": ca_bal,
            "broken_easily": False
        }
    }
