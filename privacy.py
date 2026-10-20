"""privacy.py
Consolidated Module 1 Differential Privacy (DP):
1. Laplace Mechanism: Calibrated noise for numerical count queries.
2. Exponential Mechanism: Private selection of top items.
3. Privacy Budget: Tracks epsilon spending and prevents privacy budget exhaustion.
"""

import math
import numpy as np
from typing import Dict, Tuple


def laplace_noise(scale: float) -> float:
    """Samples from Laplace(0, scale) using the inverse CDF formula:
    X = -scale * sgn(U - 0.5) * ln(1 - 2|U - 0.5|).
    """
    u = np.random.uniform(1e-10, 1.0 - 1e-10)
    diff = u - 0.5
    sgn = 1.0 if diff >= 0 else -1.0
    return float(-scale * sgn * math.log(1.0 - 2.0 * abs(diff)))


def laplace_mechanism(true_count: int, epsilon: float, sensitivity: float = 1.0) -> int:
    """Adds calibrated Laplace noise (scale = sensitivity / epsilon) to a count query."""
    if epsilon <= 0:
        raise ValueError("Epsilon must be positive")
    scale = sensitivity / epsilon
    noisy_val = true_count + laplace_noise(scale)
    return max(0, round(noisy_val))


def exponential_mechanism(scores: Dict[str, float], epsilon: float) -> Tuple[str, Dict[str, float]]:
    """Selects an item privately: P(item) is proportional to exp(epsilon * score / 2)."""
    items = list(scores.keys())
    vals = np.array([scores[k] for k in items], dtype=float)
    scaled = (epsilon * vals) / 2.0
    exp_vals = np.exp(scaled - np.max(scaled))  # Numerically stable softmax
    probs = exp_vals / np.sum(exp_vals)

    chosen_idx = np.random.choice(len(items), p=probs)
    prob_dict = {items[i]: round(float(probs[i]), 4) for i in range(len(items))}
    return items[chosen_idx], prob_dict


class PrivacyBudget:
    """Tracks privacy budget consumption (basic sequential composition: sum(epsilon) <= max_epsilon)."""
    def __init__(self, max_epsilon: float = 5.0):
        self.max_epsilon = max_epsilon
        self.spent_epsilon = 0.0

    @property
    def remaining_epsilon(self) -> float:
        return max(0.0, self.max_epsilon - self.spent_epsilon)

    @property
    def percent_consumed(self) -> float:
        return min(100.0, (self.spent_epsilon / self.max_epsilon) * 100.0)

    def spend(self, epsilon: float) -> bool:
        """Approves and deducts budget if available; refuses if budget would be exceeded."""
        if self.spent_epsilon + epsilon > self.max_epsilon + 1e-9:
            return False
        self.spent_epsilon += epsilon
        return True

    def reset(self):
        self.spent_epsilon = 0.0
