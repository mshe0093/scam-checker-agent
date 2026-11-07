"""The CLI falls back to the offline rules engine when no API key is set."""

from typer.testing import CliRunner

from scamcheck.cli import app


def test_check_without_api_key_uses_rules_engine(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("SCAMCHECK_ENGINE", "auto")
    # No links or numbers, so no tool reaches the network.
    res = CliRunner().invoke(app, ["check", "Hi, are we still on for lunch tomorrow?"])
    assert res.exit_code == 0, res.output
    assert "rules engine" in res.output
    assert "model call" not in res.output
