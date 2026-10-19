"""Privacy module for TrustLens+ covering Module 1 of syllabus:
- Laplace mechanism with inverse CDF and clipping
- Exponential mechanism for discrete item selection
- Warner's randomized response and de-biased estimation
- Basic and advanced privacy budget composition
- Multi-party secure computation and distributed differential privacy
"""

from .laplace import laplace_mechanism, laplace_inverse_cdf, evaluate_laplace_error
from .exponential import exponential_mechanism, evaluate_exponential_accuracy
from .randomized_response import (
    simulate_randomized_response, p_to_epsilon, epsilon_to_p
)
from .budget import PrivacyBudget
from .multiparty import (
    split_additive_shares, reconstruct_secret,
    sample_distributed_laplace_share, run_multiparty_dp_sum
)
