"""Step 9: Privacy Budget Manager and Composition (Module 1).
Tracks epsilon and delta expenditure across multiple statistical queries:
- Basic sequential composition: epsilon_total = sum(epsilon_i).
- Advanced composition theorem (Dwork, Rothblum, Vadhan): sub-linear bound for k queries.
- Enforces strict privacy budgeting by blocking queries when the budget is exhausted.
"""

import math
from typing import Dict, List, Optional, Any


class PrivacyBudget:
    """Manages an overall differential privacy budget for a dataset or organization."""

    def __init__(self, max_epsilon: float = 5.0, max_delta: float = 1e-4):
        if max_epsilon <= 0:
            raise ValueError("max_epsilon must be positive")
        self.max_epsilon = max_epsilon
        self.max_delta = max_delta

        self.spent_epsilon = 0.0
        self.spent_delta = 0.0
        self.query_history: List[Dict[str, Any]] = []

    @property
    def remaining_epsilon(self) -> float:
        return max(0.0, self.max_epsilon - self.spent_epsilon)

    @property
    def remaining_delta(self) -> float:
        return max(0.0, self.max_delta - self.spent_delta)

    @property
    def percent_consumed(self) -> float:
        return min(100.0, (self.spent_epsilon / self.max_epsilon) * 100.0)

    @property
    def is_exhausted(self) -> bool:
        return self.spent_epsilon >= self.max_epsilon

    def can_spend(self, epsilon: float, delta: float = 0.0) -> bool:
        """Checks whether a query with given epsilon and delta can be safely answered."""
        return (self.spent_epsilon + epsilon <= self.max_epsilon + 1e-9) and \
               (self.spent_delta + delta <= self.max_delta + 1e-9)

    def spend(self, epsilon: float, delta: float = 0.0, description: str = "") -> bool:
        """Attempts to spend privacy budget. Returns True if granted, False if refused."""
        if not self.can_spend(epsilon, delta):
            return False

        self.spent_epsilon += epsilon
        self.spent_delta += delta
        self.query_history.append({
            "query_idx": len(self.query_history) + 1,
            "epsilon": epsilon,
            "delta": delta,
            "description": description,
            "cumulative_epsilon": round(self.spent_epsilon, 4),
            "remaining_epsilon": round(self.remaining_epsilon, 4)
        })
        return True

    def reset(self):
        """Resets the budget to initial state."""
        self.spent_epsilon = 0.0
        self.spent_delta = 0.0
        self.query_history.clear()

    @staticmethod
    def advanced_composition(
        k_queries: int,
        eps_per_query: float,
        delta_prime: float = 1e-5
    ) -> float:
        """Computes advanced composition bound for k identical (eps_per_query)-DP queries:
        eps_total = sqrt(2 * k * ln(1 / delta_prime)) * eps_per_query + k * eps_per_query * (exp(eps_per_query) - 1).
        """
        if k_queries <= 0 or eps_per_query <= 0 or delta_prime <= 0:
            return 0.0

        term1 = math.sqrt(2.0 * k_queries * math.log(1.0 / delta_prime)) * eps_per_query
        term2 = k_queries * eps_per_query * (math.exp(eps_per_query) - 1.0)
        return term1 + term2
