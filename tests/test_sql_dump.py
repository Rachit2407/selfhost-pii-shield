"""Tests for SQL dump and JSONL streaming scrubbers."""

from app.api.deps import resolve_pipeline
from app.connectors.documents import scrub_document_bytes
from app.connectors.sql_dump import scrub_jsonl_lines, scrub_sql_lines


def test_scrub_sql_dump_preserves_ddl_and_scrubs_inserts():
    sql_dump = [
        "CREATE TABLE users (id INT PRIMARY KEY, email TEXT, pan TEXT);",
        "INSERT INTO users (id, email, pan) VALUES (1, 'aarav@acme.in', 'ABCDE1234F');",
        "INSERT INTO users (id, email, pan) VALUES (2, 'aarav@acme.in', 'FGHIJ5678K');",
    ]
    pipeline = resolve_pipeline("sql-salt")
    out_lines, summary = scrub_sql_lines(sql_dump, pipeline=pipeline, mode="synthetic")

    assert out_lines[0] == sql_dump[0]
    assert "aarav@acme.in" not in out_lines[1]
    assert "ABCDE1234F" not in out_lines[1]
    assert summary.findings_count >= 4

    # Same email in row 1 and row 2 must produce identical deterministic synthetic email.
    assert out_lines[1].split("'")[1] == out_lines[2].split("'")[1]


def test_scrub_jsonl_stream_and_sql_document_bytes():
    pipeline = resolve_pipeline("jsonl-salt")
    lines = [
        '{"id": 1, "email": "ops@acme.in"}',
        '{"id": 2, "upi": "ops@okaxis"}',
    ]
    out, summary = scrub_jsonl_lines(lines, pipeline=pipeline, mode="synthetic")
    assert summary.lines_processed == 2
    assert summary.findings_count >= 2
    assert "ops@acme.in" not in out[0]
    assert "ops@okaxis" not in out[1]

    sql_bytes = b"INSERT INTO t VALUES ('rachit@acme.in');\n"
    doc_res = scrub_document_bytes("export.sql", sql_bytes, pipeline=pipeline, mode="redact")
    assert doc_res.content_type == "application/sql"
    assert "[EMAIL_ADDRESS_" in doc_res.scrubbed_content
