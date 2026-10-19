"""Step 9: Warner's Randomized Response for Differential Privacy (Module 1).
Simulates local differential privacy surveys:
- Respondents answer truthfully with probability p, and randomly otherwise.
- De-biases empirical results to recover true population rates.
- Demonstrates privacy-accuracy trade-off: epsilon = ln(p / (1 - p)).
"""

import math
import numpy as np
from typing import Dict, Any, List


def p_to_epsilon(p: float) -> float:
    """Computes differential privacy parameter epsilon from truthful probability p."""
    if p <= 0.5 or p >= 1.0:
        raise ValueError("Truthful probability p must be in (0.5, 1.0)")
    return math.log(p / (1.0 - p))


def epsilon_to_p(epsilon: float) -> float:
    """Computes truthful probability p from differential privacy parameter epsilon."""
    if epsilon <= 0:
        raise ValueError("Epsilon must be strictly positive")
    return math.exp(epsilon) / (1.0 + math.exp(epsilon))


def simulate_randomized_response(
    true_rate: float,
    num_respondents: int = 5000,
    p: float = 0.75
) -> Dict[str, Any]:
    """Simulates a randomized response survey with true positive rate in population:
    Each person answers truthfully with probability p, and opposite with probability (1 - p).
    Estimates true population rate via de-biasing.
    """
    if not (0.0 <= true_rate <= 1.0):
        raise ValueError("true_rate must be in [0, 1]")
    if not (0.5 < p < 1.0):
        raise ValueError("p must be in (0.5, 1.0)")

    # Generate true underlying binary statuses (1 = Yes, 0 = No)
    true_answers = (np.random.uniform(0, 1, num_respondents) < true_rate).astype(int)

    # Randomized response: keep answer with prob p, flip with prob (1 - p)
    keep_truth = (np.random.uniform(0, 1, num_respondents) < p).astype(int)
    reported_answers = np.where(keep_truth == 1, true_answers, 1 - true_answers)

    # Empirical reported proportion
    y = float(np.mean(reported_answers))

    # De-biased estimator: E[Y] = p * pi + (1 - p) * (1 - pi) = (2p - 1) * pi + (1 - p)
    # pi_hat = (Y - (1 - p)) / (2p - 1)
    pi_hat = (y - (1.0 - p)) / (2.0 * p - 1.0)
    pi_hat_clamped = min(1.0, max(0.0, pi_hat))

    # Theoretical variance of estimator:
    # Var(pi_hat) = [p * (1 - p)] / [n * (2p - 1)^2] + [pi * (1 - pi)] / n
    var_est = (p * (1.0 - p)) / (num_respondents * ((2.0 * p - 1.0) ** 2))
    std_err = math.sqrt(var_est)

    epsilon = p_to_epsilon(p)

    return {
        "num_respondents": num_respondents,
        "true_rate": round(true_rate, 4),
        "truth_probability_p": round(p, 4),
        "epsilon": round(epsilon, 4),
        "reported_yes_rate": round(y, 4),
        "estimated_true_rate": round(pi_hat_clamped, 4),
        "estimation_error": round(abs(pi_hat_clamped - true_rate), 4),
        "theoretical_std_error": round(std_err, 4)
    }
