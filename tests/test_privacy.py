"""Unit tests for Step 9 Differential Privacy and Secure Multi-Party Computation."""

import unittest
import numpy as np
from trustlens.privacy.laplace import (
    laplace_mechanism, evaluate_laplace_error
)
from trustlens.privacy.exponential import (
    exponential_mechanism, evaluate_exponential_accuracy
)
from trustlens.privacy.randomized_response import (
    simulate_randomized_response, p_to_epsilon, epsilon_to_p
)
from trustlens.privacy.budget import PrivacyBudget
from trustlens.privacy.multiparty import (
    split_additive_shares, reconstruct_secret, run_multiparty_dp_sum
)


class TestPrivacy(unittest.TestCase):

    def test_laplace_error_matches_theory(self):
        """Checkpoint: average error matches theory (~1/epsilon)."""
        eps = 1.0
        res = evaluate_laplace_error(true_count=500, epsilon=eps, num_samples=3000)
        # Expected MAE is 1/eps = 1.0
        self.assertAlmostEqual(res["empirical_mae"], 1.0, delta=0.1)

    def test_exponential_mechanism_behavior(self):
        scores = {
            "Computer Science": 450,
            "Mechanical": 120,
            "Electrical": 110,
            "Civil": 90
        }
        # With high epsilon (e.g. 5.0), Computer Science should be chosen almost always
        top_chosen = 0
        for _ in range(100):
            chosen, _ = exponential_mechanism(scores, epsilon=5.0)
            if chosen == "Computer Science":
                top_chosen += 1
        self.assertGreaterEqual(top_chosen, 95)

    def test_randomized_response_recovery(self):
        true_rate = 0.65
        res = simulate_randomized_response(true_rate=true_rate, num_respondents=10000, p=0.80)
        self.assertAlmostEqual(res["estimated_true_rate"], true_rate, delta=0.05)

    def test_privacy_budget_blocking(self):
        budget = PrivacyBudget(max_epsilon=2.0)
        self.assertTrue(budget.spend(1.0, description="Query 1"))
        self.assertEqual(budget.remaining_epsilon, 1.0)
        self.assertTrue(budget.spend(0.8, description="Query 2"))
        self.assertAlmostEqual(budget.remaining_epsilon, 0.2)
        # Query requesting 0.5 must be rejected
        self.assertFalse(budget.spend(0.5, description="Query 3"))
        self.assertTrue(budget.spend(0.2, description="Query 4"))
        self.assertTrue(budget.is_exhausted)
        self.assertFalse(budget.spend(0.1))

    def test_multiparty_dp_sum(self):
        """Checkpoint: multiparty total equals true total plus one Laplace noise term."""
        college_counts = {
            "Tech Institute": 340,
            "National University": 520,
            "State College": 210
        }
        true_sum = sum(college_counts.values())  # 1070

        res = run_multiparty_dp_sum(college_counts, epsilon=1.0)
        self.assertEqual(res["true_sum"], true_sum)
        # Verification: noisy_total == true_sum + total_distributed_noise
        calc_noisy = true_sum + res["total_distributed_noise"]
        self.assertAlmostEqual(res["noisy_total"], calc_noisy, places=1)


if __name__ == "__main__":
    unittest.main()
