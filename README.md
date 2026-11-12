# Self-Hosted PII Shield

**100% Air-Gapped Local DB & Document PII Anonymizer**

Scrub production databases (PostgreSQL, SQLite) and sensitive documents (`.txt`, `.md`, `.csv`, `.json`, `.jsonl`, `.sql`, `.pdf`) inside your private VPC or laptop before loading them into staging environments or sending prompts to LLMs.

## Core Guarantees

- **100% Air-Gapped Capable:** Pre-baked NLP model (`en_core_web_sm`), zero outbound API calls, zero telemetry, zero external CDN dependencies in the Web UI. Even `docker-compose.yml` defaults to `internal: true` networking.
- **Deterministic Keyed Replacement:** Uses `HMAC-SHA256(PII_SHIELD_SALT, entity_type:normalized_value)` to seed local `Faker` and format-preserving generators—so identical PII maps consistently across runs, documents, and tables without storing plaintext lookup tables.
- **Referential Integrity Across Foreign Keys:** Introspects PK/FK graphs via SQLAlchemy, groups linked columns into equivalence classes via Union-Find, topologically orders parent-before-child tables, and resolves `UNIQUE` collisions deterministically across the entire FK group.

---

## 1-Click Docker Quickstart

```bash
cp .env.example .env
# Edit PII_SHIELD_SALT in .env to a strong random secret
docker compose up --build
```

Open `http://localhost:8080` for the self-contained Web UI, or call the REST API directly.

---

## Local Python & CLI Usage

```bash
pip install -e ".[dev]"
python -m spacy download en_core_web_sm
python samples/create_sample_db.py

# Start Web UI + API
pii-shield serve

# Scrub a document or LLM prompt file
pii-shield scrub-file samples/sample_incident.txt --mode synthetic

# Inspect DB foreign-key equivalence groups
pii-shield inspect-db sqlite:///samples/sample_prod.sqlite

# Anonymize production DB -> clean staging DB (never mutates source in place)
pii-shield scrub-db sqlite:///samples/sample_prod.sqlite sqlite:///samples/sample_staging.sqlite
```

---

## REST API Endpoints

- `GET /health` — Readiness probe and active detection backend (`presidio+spacy` or `regex+spacy`).
- `GET /api/v1/airgap-check` — Reports air-gap posture (`external_telemetry: false`, `outbound_network_calls: 0`).
- `POST /api/v1/scrub/text` — Scrub raw text or LLM prompts.
- `POST /api/v1/scrub/json` — Recursively scrub nested JSON payloads.
- `POST /api/v1/scrub/file` — Upload and scrub `.txt`, `.md`, `.csv`, `.json`, `.jsonl`, or `.pdf`.
- `POST /api/v1/db/inspect` — Inspect schema, topological order, FK groups, and auto-inferred PII rules.
- `POST /api/v1/db/anonymize` — Copy anonymized rows from `source_dsn` to `target_dsn` preserving all FKs.

---

## Open-Core Roadmap

- **Open-Source Core (Apache-2.0):** CLI, FastAPI engine, local Web UI, deterministic Faker/format-preserving anonymizer, SQLite/PostgreSQL FK-safe scrubber (including self-referencing FKs & `.sql` dump exports), 1-click Docker Compose.
- **Self-Hosted Enterprise Add-Ons (`app/enterprise/hooks.py`):** Clean `AuthProvider` and `AuditSink` protocol seams ready for team RBAC, tamper-evident compliance audit logs (SOC 2 / DPDP / GDPR), and SAML/OIDC SSO integration.
