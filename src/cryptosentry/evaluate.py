"""Plots: measured classical factoring time, and theoretical complexity comparison."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from cryptosentry.complexity import gnfs_operations, shor_operations


def plot_empirical_factoring_time(results: dict[int, float], out_path: Path) -> None:
    bit_sizes = sorted(results.keys())
    times = [results[b] for b in bit_sizes]

    plt.figure(figsize=(7, 5))
    plt.plot(bit_sizes, times, marker="o")
    plt.yscale("log")
    plt.xlabel("RSA modulus size (bits)")
    plt.ylabel("trial-division factoring time (seconds, log scale)")
    plt.title("measured classical factoring time vs. key size")
    plt.grid(True, which="both", alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_complexity_comparison(bit_range: list[int], out_path: Path) -> None:
    gnfs = [gnfs_operations(b) for b in bit_range]
    shor = [shor_operations(b) for b in bit_range]

    plt.figure(figsize=(7, 5))
    plt.plot(bit_range, gnfs, label="GNFS (best known classical), estimated operations")
    plt.plot(bit_range, shor, label="Shor's algorithm, estimated quantum gates")
    plt.yscale("log")
    plt.xlabel("RSA modulus size (bits)")
    plt.ylabel("estimated operation count (log scale)")
    plt.title("classical vs. quantum factoring cost: theoretical estimates only")
    plt.legend()
    plt.grid(True, which="both", alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
