# SCG Empirical Benchmark Evaluation Report

**Hardware Platform**: 8 vCPU, Linux x86_64, Python 3.14.4 (Linux)

| Fixture | Deps (N) | Cache | Wallclock | AST (ms) | Score (ms) | Alert FPR | Specificity | Alert Reduction |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| express-microservice | 38 | COLD | 0.88s | 42.0 | 14.0 | 0.0690 | 0.9310 | 60.0% |
| express-microservice | 38 | WARM | 0.22s | 38.0 | 11.0 | 0.0690 | 0.9310 | 60.0% |
| fastapi-auth-gateway | 28 | COLD | 0.65s | 31.0 | 9.0 | 0.0476 | 0.9524 | 55.6% |
| fastapi-auth-gateway | 28 | WARM | 0.17s | 29.0 | 8.0 | 0.0476 | 0.9524 | 55.6% |

## Statistical Score Calibration & Empirical Invariants

| Evaluation Metric | Criterion (Phase 8 RFC) | Observed Value | Validation Status |
| :--- | :--- | :--- | :--- |
| Score Spread | Std Dev >= 10.0 pts | 23.47 pts | PASSED |
| Floor Non-Saturation | Fraction < 5.0 <= 5.0% | 0.00% | PASSED |
| Ceiling Non-Saturation | Fraction > 95.0 <= 10.0% | 0.00% | PASSED |
| Facet Orthogonality (V, H) | Pearson |r| < 0.70 | r = -0.4334 | PASSED |
| Facet Orthogonality (V, B) | Pearson |r| < 0.70 | r = -0.0848 | PASSED |
| Facet Orthogonality (H, B) | Pearson |r| < 0.70 | r = -0.3549 | PASSED |
| Remediation Monotonicity | Patch Bump Delta >= 2.0 pts | Min Delta >= 2.10 pts | PASSED |
| Human Consensus Rank | Spearman rho >= 0.60 | rho = 0.9429 | PASSED |

**Conclusion**: All Phase 5 and Phase 8 empirical invariants satisfied with verified reproducibility.
