"""Air-gap verification tests: zero outbound network calls and zero external CDN links."""

from pathlib import Path
import socket

from app.engine.deterministic import DeterministicAnonymizer
from app.engine.detector import LocalPIIDetector
from app.engine.pipeline import PIIShieldPipeline


def test_zero_outbound_network_calls_during_init_and_scrub(monkeypatch):
    def _blocked_connect(*args, **kwargs):
        raise AssertionError(f"Outbound network call attempted in air-gap mode: {args} {kwargs}")

    monkeypatch.setattr(socket, "create_connection", _blocked_connect)
    monkeypatch.setattr(socket.socket, "connect", _blocked_connect)

    detector = LocalPIIDetector(score_threshold=0.4, airgap_strict=True)
    pipeline = PIIShieldPipeline(
        detector=detector,
        anonymizer=DeterministicAnonymizer(salt="airgap-salt", locale="en_IN"),
    )
    res = pipeline.scrub_text(
        "Email aarav@acme.in, PAN ABCDE1234F, UPI aarav@okicici, site https://acme.in"
    )
    assert "aarav@acme.in" not in res.scrubbed_text
    assert "ABCDE1234F" not in res.scrubbed_text
    assert "aarav@okicici" not in res.scrubbed_text


def test_web_ui_has_zero_external_cdn_links():
    static_dir = Path(__file__).resolve().parent.parent / "app" / "static"
    for asset in ("index.html", "styles.css", "app.js"):
        content = (static_dir / asset).read_text(encoding="utf-8")
        assert "http://" not in content
        assert "https://" not in content
