"""FastAPI endpoint and air-gap compliance tests."""

import io
import json
from pathlib import Path
import sqlite3

from fastapi.testclient import TestClient

from app.enterprise.hooks import AuditEvent, LocalJsonlAuditSink
from app.main import app

client = TestClient(app)


def test_health_and_airgap_check():
    r_health = client.get("/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "ok"

    r_airgap = client.get("/api/v1/airgap-check")
    assert r_airgap.status_code == 200
    body = r_airgap.json()
    assert body["airgap_strict"] is True
    assert body["external_telemetry"] is False
    assert body["outbound_network_calls"] == 0


def test_scrub_text_and_consistency():
    payload = {
        "text": "Email rachit@acme.in and repeat rachit@acme.in with PAN ABCDE1234F.",
        "mode": "synthetic",
        "salt": "api-test-salt",
    }
    resp = client.post("/api/v1/scrub/text", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "rachit@acme.in" not in data["scrubbed_text"]
    assert "ABCDE1234F" not in data["scrubbed_text"]
    assert data["findings_count"] >= 3
    # Same email appears twice and should produce the same synthetic replacement twice.
    email_replacements = [
        f["replacement"] for f in data["findings"] if f["entity_type"] == "EMAIL_ADDRESS"
    ]
    assert len(email_replacements) == 2
    assert email_replacements[0] == email_replacements[1]


def test_scrub_json_and_file_upload():
    json_resp = client.post(
        "/api/v1/scrub/json",
        json={"payload": {"user": {"email": "dev@acme.in", "upi": "dev@okaxis"}}},
    )
    assert json_resp.status_code == 200
    scrubbed = json_resp.json()["scrubbed_payload"]
    assert scrubbed["user"]["email"].endswith("@synthetic.local")
    assert scrubbed["user"]["upi"].endswith("@upi.synthetic")

    csv_bytes = b"id,email,notes\n1,ops@acme.in,Call +91-9876543210\n"
    file_resp = client.post(
        "/api/v1/scrub/file",
        files={"file": ("users.csv", io.BytesIO(csv_bytes), "text/csv")},
        data={"mode": "redact"},
    )
    assert file_resp.status_code == 200
    content = file_resp.json()["scrubbed_content"]
    assert "ops@acme.in" not in content
    assert "[EMAIL_ADDRESS_" in content
    assert json.loads(json.dumps(file_resp.json()))["findings_count"] >= 2


def test_web_ui_and_db_api_endpoints(tmp_path: Path):
    ui_resp = client.get("/")
    assert ui_resp.status_code == 200
    assert "PII Shield" in ui_resp.text

    js_resp = client.get("/static/app.js")
    assert js_resp.status_code == 200

    src_db = tmp_path / "api_prod.sqlite"
    tgt_db = tmp_path / "api_staging.sqlite"
    conn = sqlite3.connect(src_db)
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL);
        INSERT INTO users VALUES (1, 'rachit@acme.in');
        """
    )
    conn.commit()
    conn.close()

    src_dsn = f"sqlite:///{src_db.as_posix()}"
    tgt_dsn = f"sqlite:///{tgt_db.as_posix()}"

    inspect_resp = client.post("/api/v1/db/inspect", json={"source_dsn": src_dsn})
    assert inspect_resp.status_code == 200
    assert inspect_resp.json()["topological_order"] == ["users"]

    anon_resp = client.post(
        "/api/v1/db/anonymize",
        json={"source_dsn": src_dsn, "target_dsn": tgt_dsn, "mode": "synthetic"},
    )
    assert anon_resp.status_code == 200
    assert anon_resp.json()["rows_copied"] == {"users": 1}


def test_local_audit_sink_records_metadata_without_raw_pii(tmp_path: Path):
    log_file = tmp_path / "audit.jsonl"
    sink = LocalJsonlAuditSink(log_file)
    sink.record(
        AuditEvent(
            action="scrub_text",
            backend="presidio+spacy",
            findings_count=2,
            entity_counts={"EMAIL_ADDRESS": 1, "IN_PAN": 1},
        )
    )
    saved = json.loads(log_file.read_text(encoding="utf-8").strip())
    assert saved["action"] == "scrub_text"
    assert saved["findings_count"] == 2
    assert saved["entity_counts"] == {"EMAIL_ADDRESS": 1, "IN_PAN": 1}
