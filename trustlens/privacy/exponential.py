"""Step 9: Exponential Mechanism for Differential Privacy (Module 1).
Selects a discrete item d from candidate domain D with probability:
P(d) proportional to exp(epsilon * score(d) / (2 * Delta)).
Demonstrates that small epsilon approaches uniform random selection,
while large epsilon almost deterministically selects the optimal item.
"""

import numpy as np
from typing import Dict, List, Tuple, Any


def exponential_mechanism(
    scores: Dict[str, float],
    epsilon: float,
    delta_sensitivity: float = 1.0
) -> Tuple[str, Dict[str, float]]:
    """Selects an item using the Exponential Mechanism.
    Returns (selected_item_name, probability_distribution_dict).
    """
    if epsilon <= 0:
        raise ValueError("Epsilon must be strictly positive")

    items = list(scores.keys())
    score_vals = np.array([scores[k] for k in items], dtype=np.float64)

    # Exponent: (epsilon * score) / (2 * delta)
    scaled_scores = (epsilon * score_vals) / (2.0 * delta_sensitivity)

    # Numerically stable softmax: subtract max value
    max_score = np.max(scaled_scores)
    exp_scores = np.exp(scaled_scores - max_score)
    probabilities = exp_scores / np.sum(exp_scores)

    # Sample from categorical distribution
    chosen_idx = np.random.choice(len(items), p=probabilities)
    chosen_item = items[chosen_idx]

    prob_dict = {items[i]: round(float(probabilities[i]), 5) for i in range(len(items))}
    return chosen_item, prob_dict


def evaluate_exponential_accuracy(
    scores: Dict[str, float],
    epsilon_values: List[float],
    trials_per_eps: int = 1000,
    delta_sensitivity: float = 1.0
) -> List[Dict[str, Any]]:
    """Evaluates the probability of choosing the true top-scoring department as epsilon varies."""
    true_top = max(scores.keys(), key=lambda k: scores[k])
    results = []

    for eps in epsilon_values:
        top_chosen_count = 0
        for _ in range(trials_per_eps):
            chosen, _ = exponential_mechanism(scores, eps, delta_sensitivity)
            if chosen == true_top:
                top_chosen_count += 1

        accuracy = top_chosen_count / trials_per_eps
        results.append({
            "epsilon": eps,
            "true_top_item": true_top,
            "accuracy": round(accuracy, 4),
            "trials": trials_per_eps
        })

    return results
