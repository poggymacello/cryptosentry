from cryptosentry.factoring import benchmark_trial_division, trial_division_factor


def test_trial_division_factors_known_composite():
    p, q = trial_division_factor(35)
    assert {p, q} == {5, 7}


def test_trial_division_handles_even_numbers():
    p, q = trial_division_factor(100)
    assert p * q == 100
    assert p == 2


def test_trial_division_on_prime_returns_1_and_n():
    p, q = trial_division_factor(97)
    assert (p, q) == (1, 97)


def test_benchmark_returns_correct_and_increasing_timings():
    results = benchmark_trial_division([12, 16, 20], seed=1)
    assert set(results.keys()) == {12, 16, 20}
    assert all(t >= 0 for t in results.values())
