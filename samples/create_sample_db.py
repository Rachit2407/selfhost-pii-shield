"""Generate a realistic synthetic sample SQLite database with FK relationships."""

from pathlib import Path
import sqlite3

DB_PATH = Path(__file__).resolve().parent / "sample_prod.sqlite"


def build_sample_db() -> Path:
    if DB_PATH.exists():
        DB_PATH.unlink()

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")

    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            pan_number TEXT UNIQUE NOT NULL
        );

        CREATE TABLE orders (
            order_id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            customer_email TEXT NOT NULL,
            upi_id TEXT NOT NULL,
            amount_inr INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (customer_email) REFERENCES users(email)
        );

        CREATE TABLE support_tickets (
            ticket_id INTEGER PRIMARY KEY,
            order_id INTEGER NOT NULL,
            reporter_email TEXT NOT NULL,
            notes TEXT NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(order_id),
            FOREIGN KEY (reporter_email) REFERENCES users(email)
        );

        INSERT INTO users (id, email, full_name, phone, pan_number) VALUES
            (1, 'aarav.sharma@acme-fintech.in', 'Aarav Sharma', '+91-9876543210', 'ABCDE1234F'),
            (2, 'priya.nair@acme-fintech.in', 'Priya Nair', '+91-9811223344', 'FGHIJ5678K');

        INSERT INTO orders (order_id, user_id, customer_email, upi_id, amount_inr) VALUES
            (101, 1, 'aarav.sharma@acme-fintech.in', 'aarav.sharma@okicici', 4999),
            (102, 2, 'priya.nair@acme-fintech.in', 'priya.nair@oksbi', 1299);

        INSERT INTO support_tickets (ticket_id, order_id, reporter_email, notes) VALUES
            (5001, 101, 'aarav.sharma@acme-fintech.in',
             'Aarav Sharma called from +91-9876543210 about PAN ABCDE1234F verification.'),
            (5002, 102, 'priya.nair@acme-fintech.in',
             'Priya Nair requested refund to priya.nair@oksbi from IP 198.51.100.77.');
        """
    )
    conn.commit()
    conn.close()
    return DB_PATH


if __name__ == "__main__":
    out = build_sample_db()
    print(f"Created sample DB at {out}")
