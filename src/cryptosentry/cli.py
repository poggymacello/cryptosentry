"""Command-line entry point: ``python -m cryptosentry train|eval``."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptosentry import evaluate as eval_mod
from cryptosentry.factoring import benchmark_trial_division
from cryptosentry.rsa import decrypt, encrypt, generate_keypair

DEMO_MESSAGE = b"rsa!"
TRIAL_DIVISION_BIT_SIZES = [16, 20, 24, 28]
COMPLEXITY_BIT_RANGE = list(range(16, 2049, 32))


def _run_pipeline(keypair_bits: int, seed: int) -> dict:
    keypair = generate_keypair(bits=keypair_bits, seed=seed)
    ciphertext = encrypt(DEMO_MESSAGE, keypair.n, keypair.e)
    recovered = decrypt(ciphertext, keypair.n, keypair.d)
    round_trip_ok = recovered == DEMO_MESSAGE

    benchmark = benchmark_trial_division(TRIAL_DIVISION_BIT_SIZES, seed=seed)

    return {
        "keypair": keypair,
        "round_trip_ok": round_trip_ok,
        "benchmark": benchmark,
    }


def cmd_train(args: argparse.Namespace) -> None:
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    result = _run_pipeline(args.keypair_bits, args.seed)
    keypair = result["keypair"]

    summary = {
        "keypair_bits": keypair.bit_length,
        "round_trip_ok": result["round_trip_ok"],
        "trial_division_seconds_by_bit_size": {
            str(b): round(t, 6) for b, t in result["benchmark"].items()
        },
    }
    (out_dir / "metrics.json").write_text(json.dumps(summary, indent=2))

    eval_mod.plot_empirical_factoring_time(result["benchmark"], out_dir / "factoring_time.png")
    eval_mod.plot_complexity_comparison(
        COMPLEXITY_BIT_RANGE, out_dir / "quantum_analysis.png"
    )

    print(json.dumps(summary, indent=2))
    print(f"\nartifacts written to {out_dir}/")


def cmd_eval(args: argparse.Namespace) -> None:
    result = _run_pipeline(args.keypair_bits, args.seed)
    print(f"keypair bits: {result['keypair'].bit_length}")
    print(f"round-trip ok: {result['round_trip_ok']}")
    print(f"trial-division benchmark: {result['benchmark']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptosentry")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--keypair-bits", type=int, default=256)
    common.add_argument("--seed", type=int, default=42)

    train_p = sub.add_parser("train", parents=[common], help="run + evaluate + save artifacts")
    train_p.add_argument("--output-dir", default="assets")
    train_p.set_defaults(func=cmd_train)

    eval_p = sub.add_parser(
        "eval", parents=[common], help="re-run the deterministic pipeline and print metrics"
    )
    eval_p.set_defaults(func=cmd_eval)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
