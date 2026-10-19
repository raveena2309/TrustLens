"""Step 9: Laplace Mechanism for Differential Privacy (Module 1).
Implements:
1. Laplace noise generation via inverse CDF from scratch.
2. Calibrated noise: b = Delta / epsilon.
3. Clamping and integer rounding for count queries.
4. Theoretical vs empirical error distribution analysis (E[|Noise|] = 1/epsilon for Delta=1).
"""

import math
import numpy as np
from typing import Union, List, Dict, Optional


def laplace_inverse_cdf(scale: float, u: Optional[float] = None) -> float:
    """Generates a sample from Laplace(0, scale) using the inverse CDF formula:
    X = -scale * sgn(U - 0.5) * ln(1 - 2|U - 0.5|)
    where U is Uniform(0, 1).
    """
    if u is None:
        u = float(np.random.uniform(1e-12, 1.0 - 1e-12))
    diff = u - 0.5
    sgn = 1.0 if diff >= 0 else -1.0
    val = -scale * sgn * math.log(1.0 - 2.0 * abs(diff))
    return float(val)


def laplace_mechanism(
    true_count: int,
    epsilon: float,
    delta_sensitivity: float = 1.0,
    clamp_non_negative: bool = True,
    round_integer: bool = True
) -> float:
    """Adds calibrated Laplace noise to a count query.
    Scale b = delta_sensitivity / epsilon.
    """
    if epsilon <= 0:
        raise ValueError("Epsilon must be strictly positive")

    scale = delta_sensitivity / epsilon
    noise = laplace_inverse_cdf(scale)
    noisy_val = true_count + noise

    if clamp_non_negative:
        noisy_val = max(0.0, noisy_val)
    if round_integer:
        noisy_val = round(noisy_val)

    return noisy_val


def evaluate_laplace_error(
    true_count: int,
    epsilon: float,
    num_samples: int = 1000,
    delta_sensitivity: float = 1.0
) -> Dict[str, float]:
    """Generates empirical noise samples and evaluates Mean Absolute Error against theoretical expectation."""
    scale = delta_sensitivity / epsilon
    theoretical_mae = scale  # E[|X|] for Laplace(0, b) is b

    errors = []
    for _ in range(num_samples):
        noisy = laplace_mechanism(true_count, epsilon, delta_sensitivity, clamp_non_negative=False, round_integer=False)
        errors.append(abs(noisy - true_count))

    empirical_mae = float(np.mean(errors))
    std_err = float(np.std(errors) / math.sqrt(num_samples))

    return {
        "epsilon": epsilon,
        "scale": round(scale, 4),
        "theoretical_mae": round(theoretical_mae, 4),
        "empirical_mae": round(empirical_mae, 4),
        "std_error": round(std_err, 4),
        "num_samples": num_samples
    }
