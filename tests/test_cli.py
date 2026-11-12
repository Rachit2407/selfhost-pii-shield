"""CLI tests using Typer CliRunner."""

import json
from pathlib import Path

from typer.testing import CliRunner

from app.cli import cli

runner = CliRunner()


def test_cli_scrub_file(tmp_path: Path):
    src = tmp_path / "note.txt"
    out = tmp_path / "note_clean.txt"
    src.write_text("Reach Aarav at aarav@acme.in or PAN ABCDE1234F.", encoding="utf-8")

    result = runner.invoke(
        cli,
        ["scrub-file", str(src), "--out", str(out), "--mode", "synthetic", "--salt", "cli-salt"],
    )
    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary["status"] == "ok"
    assert summary["findings_count"] >= 2

    cleaned = out.read_text(encoding="utf-8")
    assert "aarav@acme.in" not in cleaned
    assert "ABCDE1234F" not in cleaned
