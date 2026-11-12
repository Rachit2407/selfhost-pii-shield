"""Typer CLI for air-gapped file & database PII anonymization."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import typer
import uvicorn

from app.api.deps import resolve_pipeline
from app.config import get_settings
from app.connectors.database import anonymize_database, inspect_database
from app.connectors.documents import scrub_document_bytes
from app.engine.deterministic import AnonymizeMode

cli = typer.Typer(
    name="pii-shield",
    help="100% air-gapped local PII redactor and deterministic synthetic DB anonymizer.",
    no_args_is_help=True,
)


@cli.command("serve")
def cmd_serve(
    host: str = typer.Option(None, help="Bind host (defaults to PII_SHIELD_HOST)."),
    port: int = typer.Option(None, help="Bind port (defaults to PII_SHIELD_PORT)."),
) -> None:
    """Start the local FastAPI + Web UI server."""
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=host or settings.host,
        port=port or settings.port,
        reload=False,
    )


@cli.command("scrub-file")
def cmd_scrub_file(
    input_path: Path = typer.Argument(..., exists=True, readable=True),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Output file path."),
    mode: AnonymizeMode = typer.Option("synthetic", "--mode", "-m"),
    salt: Optional[str] = typer.Option(None, "--salt", help="Override HMAC salt."),
) -> None:
    """Scrub a local document (TXT, MD, JSON, JSONL, CSV, PDF) offline."""
    pipeline = resolve_pipeline(salt)
    res = scrub_document_bytes(
        filename=input_path.name,
        raw_bytes=input_path.read_bytes(),
        pipeline=pipeline,
        mode=mode,
    )
    if out:
        out.write_text(res.scrubbed_content, encoding="utf-8")
        typer.echo(
            json.dumps(
                {
                    "status": "ok",
                    "output": str(out),
                    "findings_count": res.findings_count,
                    "entity_counts": res.entity_counts,
                    "backend": res.backend,
                },
                indent=2,
            )
        )
    else:
        typer.echo(res.scrubbed_content)


@cli.command("inspect-db")
def cmd_inspect_db(
    source_dsn: str = typer.Argument(..., help="SQLAlchemy source DSN."),
) -> None:
    """Inspect database schema, FK equivalence classes, and suggested PII rules."""
    report = inspect_database(source_dsn)
    typer.echo(json.dumps(asdict(report), indent=2))


@cli.command("scrub-db")
def cmd_scrub_db(
    source_dsn: str = typer.Argument(..., help="Source database DSN."),
    target_dsn: str = typer.Argument(..., help="Target staging database DSN."),
    mode: AnonymizeMode = typer.Option("synthetic", "--mode", "-m"),
    salt: Optional[str] = typer.Option(None, "--salt", help="Override HMAC salt."),
    rules_json: Optional[Path] = typer.Option(
        None, "--rules", help="Optional JSON file mapping 'table.column' -> ENTITY_TYPE."
    ),
) -> None:
    """Anonymize source_dsn into target_dsn preserving FK referential integrity."""
    column_rules = json.loads(rules_json.read_text(encoding="utf-8")) if rules_json else None
    pipeline = resolve_pipeline(salt)
    report = anonymize_database(
        source_dsn=source_dsn,
        target_dsn=target_dsn,
        pipeline=pipeline,
        mode=mode,
        column_rules=column_rules,
    )
    typer.echo(json.dumps(asdict(report), indent=2))


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
