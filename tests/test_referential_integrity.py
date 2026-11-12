"""Tests for FK-preserving relational database anonymization."""

import sqlite3
from pathlib import Path

import pytest

from app.api.deps import resolve_pipeline
from app.connectors.database import anonymize_database, inspect_database
from app.engine.pipeline import PIIShieldPipeline


def _make_pipeline(salt: str = "test-db-salt") -> PIIShieldPipeline:
    return resolve_pipeline(salt)


def _create_fk_sqlite(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            pan_number TEXT UNIQUE NOT NULL
        );
        CREATE TABLE orders (
            order_id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            customer_email TEXT NOT NULL,
            amount INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (customer_email) REFERENCES users(email)
        );
        CREATE TABLE tickets (
            ticket_id INTEGER PRIMARY KEY,
            order_id INTEGER NOT NULL,
            reporter_email TEXT NOT NULL,
            notes TEXT NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(order_id),
            FOREIGN KEY (reporter_email) REFERENCES users(email)
        );

        INSERT INTO users VALUES
            (1, 'aarav@acme.in', 'Aarav Sharma', 'ABCDE1234F'),
            (2, 'priya@acme.in', 'Priya Nair', 'FGHIJ5678K');
        INSERT INTO orders VALUES
            (10, 1, 'aarav@acme.in', 500),
            (11, 2, 'priya@acme.in', 900);
        INSERT INTO tickets VALUES
            (100, 10, 'aarav@acme.in', 'Contact aarav@acme.in about PAN ABCDE1234F'),
            (101, 11, 'priya@acme.in', 'User priya@acme.in requested invoice');
        """
    )
    conn.commit()
    conn.close()


def test_fk_integrity_and_topological_order_preserved(tmp_path: Path):
    src_db = tmp_path / "prod.sqlite"
    tgt_db = tmp_path / "staging.sqlite"
    _create_fk_sqlite(src_db)

    src_dsn = f"sqlite:///{src_db.as_posix()}"
    tgt_dsn = f"sqlite:///{tgt_db.as_posix()}"

    inspection = inspect_database(src_dsn)
    assert inspection.topological_order.index("users") < inspection.topological_order.index("orders")
    assert inspection.topological_order.index("orders") < inspection.topological_order.index("tickets")

    report = anonymize_database(
        source_dsn=src_dsn,
        target_dsn=tgt_dsn,
        pipeline=_make_pipeline(),
        mode="synthetic",
    )
    assert report.rows_copied == {"users": 2, "orders": 2, "tickets": 2}

    conn = sqlite3.connect(tgt_db)
    conn.execute("PRAGMA foreign_keys = ON;")
    fk_violations = conn.execute("PRAGMA foreign_key_check;").fetchall()
    assert fk_violations == []

    # Verify joins across users -> orders -> tickets still match and real emails are gone.
    joined = conn.execute(
        """
        SELECT u.email, o.customer_email, t.reporter_email, t.notes
        FROM users u
        JOIN orders o ON o.customer_email = u.email
        JOIN tickets t ON t.reporter_email = u.email
        ORDER BY u.id
        """
    ).fetchall()
    assert len(joined) == 2
    for u_email, o_email, t_email, notes in joined:
        assert u_email == o_email == t_email
        assert "@synthetic.local" in u_email
        assert "acme.in" not in u_email
        assert "acme.in" not in notes
        assert u_email in notes
    conn.close()


def test_refuses_in_place_mutation(tmp_path: Path):
    src_db = tmp_path / "prod.sqlite"
    _create_fk_sqlite(src_db)
    dsn = f"sqlite:///{src_db.as_posix()}"
    with pytest.raises(ValueError, match="Refusing in-place mutation"):
        anonymize_database(dsn, dsn, pipeline=_make_pipeline())


def test_self_referencing_fk_preserves_parent_before_child_order(tmp_path: Path):
    src_db = tmp_path / "self_fk_prod.sqlite"
    tgt_db = tmp_path / "self_fk_staging.sqlite"

    conn = sqlite3.connect(src_db)
    conn.execute("PRAGMA foreign_keys = OFF;")
    conn.executescript(
        """
        CREATE TABLE employees (
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            manager_email TEXT,
            FOREIGN KEY (manager_email) REFERENCES employees(email)
        );
        -- Intentionally insert subordinate row (id=1) before manager row (id=2).
        INSERT INTO employees (id, email, manager_email) VALUES
            (1, 'junior@acme.in', 'lead@acme.in'),
            (2, 'lead@acme.in', NULL);
        """
    )
    conn.commit()
    conn.close()

    report = anonymize_database(
        source_dsn=f"sqlite:///{src_db.as_posix()}",
        target_dsn=f"sqlite:///{tgt_db.as_posix()}",
        pipeline=_make_pipeline("self-fk-salt"),
        mode="synthetic",
    )
    assert report.rows_copied == {"employees": 2}

    tgt = sqlite3.connect(tgt_db)
    tgt.execute("PRAGMA foreign_keys = ON;")
    assert tgt.execute("PRAGMA foreign_key_check;").fetchall() == []
    rows = tgt.execute(
        "SELECT id, email, manager_email FROM employees ORDER BY id"
    ).fetchall()
    assert rows[0][2] == rows[1][1]
    assert "@synthetic.local" in rows[0][1]
    tgt.close()


def test_batched_streaming_preserves_fk_joins(tmp_path: Path):
    src_db = tmp_path / "batch_prod.sqlite"
    tgt_db = tmp_path / "batch_staging.sqlite"
    _create_fk_sqlite(src_db)

    report = anonymize_database(
        source_dsn=f"sqlite:///{src_db.as_posix()}",
        target_dsn=f"sqlite:///{tgt_db.as_posix()}",
        pipeline=_make_pipeline("batch-salt"),
        mode="synthetic",
        batch_size=1,
    )
    assert report.rows_copied == {"users": 2, "orders": 2, "tickets": 2}

    tgt = sqlite3.connect(tgt_db)
    tgt.execute("PRAGMA foreign_keys = ON;")
    assert tgt.execute("PRAGMA foreign_key_check;").fetchall() == []
    joined = tgt.execute(
        "SELECT u.email, o.customer_email FROM users u JOIN orders o ON o.customer_email = u.email"
    ).fetchall()
    assert len(joined) == 2
    tgt.close()
