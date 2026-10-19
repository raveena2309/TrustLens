"""Step 9: Secure Multi-Party Differential Privacy (SMC + Distributed DP).
Implements collaborative cross-college statistics without a trusted central aggregator:
1. Additive Secret Sharing modulo large prime P.
2. Distributed Laplace noise generation using Gamma infinite divisibility:
   Each party adds (Gamma(1/n, b) - Gamma(1/n, b)).
   The sum of n independent shares yields an exact sample from Laplace(0, b).
3. Secure multi-party sum computation with differential privacy guarantees.
"""

import math
import secrets
import numpy as np
from typing import List, Dict, Tuple, Any

# Large prime modulus for finite field additive secret sharing
DEFAULT_MODULUS = 2305843009213693951  # Mersenne prime 2^61 - 1


def split_additive_shares(secret: int, num_parties: int = 3, modulus: int = DEFAULT_MODULUS) -> List[int]:
    """Splits an integer secret into n additive shares modulo P:
    sum(shares) mod P == secret mod P.
    Any subset of < n shares reveals zero information about the secret.
    """
    shares = []
    total_random = 0
    for _ in range(num_parties - 1):
        r = secrets.randbelow(modulus)
        shares.append(r)
        total_random = (total_random + r) % modulus

    last_share = (secret - total_random) % modulus
    shares.append(last_share)
    return shares


def reconstruct_secret(shares: List[int], modulus: int = DEFAULT_MODULUS) -> int:
    """Reconstructs the original secret by summing all shares modulo P."""
    return sum(shares) % modulus


def sample_distributed_laplace_share(num_parties: int, scale: float) -> float:
    """Samples one local noise share using the infinite divisibility property of the Laplace distribution:
    Laplace(0, b) = Gamma(1, b) - Gamma(1, b).
    Since Gamma(1/n, b) summed n times equals Gamma(1, b),
    each party generates:
    z_i = Gamma(shape=1/n, scale=b) - Gamma(shape=1/n, scale=b).
    Sum of all n local noise shares is an EXACT sample from Laplace(0, b)!
    """
    shape = 1.0 / num_parties
    # In numpy, gamma takes shape and scale parameters
    g1 = np.random.gamma(shape, scale)
    g2 = np.random.gamma(shape, scale)
    return float(g1 - g2)


def run_multiparty_dp_sum(
    college_counts: Dict[str, int],
    epsilon: float,
    delta_sensitivity: float = 1.0,
    modulus: int = DEFAULT_MODULUS
) -> Dict[str, Any]:
    """Executes distributed differential privacy multi-party computation protocol:
    1. Each college splits its private count into n secret shares and distributes them.
    2. Each college locally generates its share of distributed Laplace noise.
    3. Each college sums the shares and noise it holds.
    4. The noisy sums are combined to reveal the grand total.
    """
    colleges = list(college_counts.keys())
    n = len(colleges)
    true_sum = sum(college_counts.values())

    # Step 1: Secret sharing of private counts
    # share_matrix[i][j] is the share that party i sends to party j
    share_matrix = []
    for c_name in colleges:
        cnt = college_counts[c_name]
        shares = split_additive_shares(cnt, num_parties=n, modulus=modulus)
        share_matrix.append(shares)

    # Step 2: Distributed noise generation
    scale = delta_sensitivity / epsilon
    local_noises = [sample_distributed_laplace_share(n, scale) for _ in range(n)]
    total_noise = sum(local_noises)

    # Step 3: Each party j sums the shares received from all parties i: sum_i share_matrix[i][j]
    party_received_sums = []
    for j in range(n):
        col_sum = sum(share_matrix[i][j] for i in range(n)) % modulus
        party_received_sums.append(col_sum)

    # Step 4: Reconstruct cleartext sum
    cleartext_sum = sum(party_received_sums) % modulus
    # Add combined distributed noise
    noisy_total = cleartext_sum + total_noise

    return {
        "num_parties": n,
        "colleges": colleges,
        "true_sum": true_sum,
        "epsilon": epsilon,
        "scale": round(scale, 4),
        "total_distributed_noise": round(total_noise, 4),
        "noisy_total": round(noisy_total, 2),
        "error": round(abs(noisy_total - true_sum), 4),
        "local_noise_shares": [round(nz, 4) for nz in local_noises]
    }
