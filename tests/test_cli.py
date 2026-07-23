import json

from cryptosentry.cli import main


def test_train_command_writes_artifacts(tmp_path):
    out_dir = tmp_path / "assets"
    main(["train", "--keypair-bits", "64", "--seed", "1", "--output-dir", str(out_dir)])

    assert (out_dir / "metrics.json").exists()
    assert (out_dir / "factoring_time.png").exists()
    assert (out_dir / "quantum_analysis.png").exists()

    metrics = json.loads((out_dir / "metrics.json").read_text())
    assert metrics["round_trip_ok"] is True
    assert "trial_division_seconds_by_bit_size" in metrics


def test_eval_command_runs_without_error(capsys):
    main(["eval", "--keypair-bits", "64", "--seed", "1"])
    captured = capsys.readouterr()
    assert "round-trip ok: True" in captured.out
