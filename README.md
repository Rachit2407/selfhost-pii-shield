# Self-Hosted PII Shield

[![CI](https://github.com/Rachit2407/selfhost-pii-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/Rachit2407/selfhost-pii-shield/actions)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/docker-1--click-2496ED?logo=docker&logoColor=white)
![Air-Gapped](https://img.shields.io/badge/air--gapped-100%25-10B981)

**100% Air-Gapped Local DB & Document PII Anonymizer**

Scrub production databases (PostgreSQL, SQLite) and sensitive documents (`.txt`, `.md`, `.csv`, `.json`, `.jsonl`, `.sql`, `.pdf`) inside your private VPC or laptop before loading them into staging environments or passing prompts to external LLMs.

---

## Architecture & Data Flow

```
[ Your VPC / Internal Network ]
────────────────────────────────────────────────────────────────────────
 Production DB (Read-Only)  ─┐
 Sensitive Incident Logs    ─┼──▶ [ PII Shield Container ]
 Developer Prompts for LLM  ─┘         │
                                       ▼
                       ┌───────────────────────────────┐
                       │  Offline Presidio + spaCy NER │
                       │  Indian + Global Regex Specs  │
                       │  Keyed HMAC-SHA256 Derivation │
                       │  Deterministic Faker Seeding  │
                       └───────────────┬───────────────┘
                                       │
     ┌─────────────────────────────────┴─────────────────────────────────┐
     ▼                                                                   ▼
[ Sanitized Staging DB ]                                      [ Scrubbed LLM Prompt ]
(Preserves 100% of FK joins & unique constraints)             (Zero customer PII leaves VPC)
```

---

## Core Guarantees

- **100% Air-Gapped Capable:** Pre-baked NLP model (`en_core_web_sm`), zero outbound API calls, zero telemetry, zero external CDN dependencies in the Web UI.
- **Deterministic Keyed Replacement:** Uses `HMAC-SHA256(PII_SHIELD_SALT, entity_type:normalized_value)` to seed local `Faker` and format-preserving generators—so identical PII maps consistently across runs, documents, and tables without storing plaintext lookup tables.
- **Referential Integrity Across Foreign Keys:** Introspects PK/FK graphs via SQLAlchemy, groups linked columns into equivalence classes via Union-Find, topologically orders parent-before-child tables (including self-referencing FKs), and resolves `UNIQUE` collisions deterministically across the entire FK group.

---

## Supported Detectors & Entities

| Entity Type | Recognition Engine | Format Preservation / Validation |
| :--- | :--- | :--- |
| **`EMAIL_ADDRESS`** | Presidio + Regex | Deterministic handle + `@synthetic.local` |
| **`PHONE_NUMBER`** | Presidio + Regex | Preserves country prefix (`+91-`, `+1-`), non-routable synthetic digits |
| **`IN_PAN`** | Regex (`[A-Z]{5}[0-9]{4}[A-Z]`) | Valid format-preserving synthetic PAN |
| **`IN_AADHAAR`** | Regex + Context | **Verhoeff checksum validated**, format-preserving spacing |
| **`IN_UPI`** | Regex (`*@okaxis`, `*@oksbi`, etc.) | Deterministic synthetic VPA handle |
| **`CREDIT_CARD`** | Presidio + Regex | **Luhn algorithm checksum validated** |
| **`SECRET_TOKEN`** | High-Precision Regex | AWS `AKIA...`, JWTs, OpenAI/Stripe `sk-...`, GitHub PATs |
| **`US_SSN`** | Presidio + Regex | 900-series unissued synthetic numbers |
| **`IP_ADDRESS`** | Presidio + Regex | RFC 1918 private synthetic range (`10.x.y.z`) |
| **`PERSON` / `ORG`** | Presidio + spaCy NER | Seeded deterministic Faker generation |

---

## 1-Click Docker Quickstart

```bash
cp .env.example .env
# Edit PII_SHIELD_SALT in .env to a strong random secret
docker compose up --build
```

Open **http://localhost:8080** for the self-contained Web UI, or call the REST API directly.

---

## LLM Pre-Sanitization Example (Python)

Drop PII Shield in front of your OpenAI, Anthropic, or DeepSeek API calls:

```python
import requests

def sanitize_for_llm(prompt: str) -> str:
    res = requests.post(
        "http://localhost:8080/api/v1/scrub/text",
        json={"text": prompt, "mode": "synthetic"}
    ).json()
    return res["scrubbed_text"]

raw_prompt = "Customer Aarav Sharma (aarav@acme.in, PAN ABCDE1234F) has a billing error."
safe_prompt = sanitize_for_llm(raw_prompt)
# Output: "Customer Maya Verma (maya.verma.7fa1@synthetic.local, PAN NZPPW3333E) has a billing error."
```

---

## Local Python & CLI Usage

```bash
# Setup virtual environment
python -m venv .venv
.\.venv\Scripts\activate  # Windows
pip install -e ".[dev]"
python -m spacy download en_core_web_sm
python samples/create_sample_db.py

# Start Web UI + API
pii-shield serve

# Scrub a document or LLM prompt file (.txt, .md, .csv, .json, .jsonl, .sql, .pdf)
pii-shield scrub-file samples/sample_incident.txt --mode synthetic

# Inspect DB foreign-key equivalence groups
pii-shield inspect-db sqlite:///samples/sample_prod.sqlite

# Anonymize production DB -> clean staging DB (never mutates source in place)
pii-shield scrub-db sqlite:///samples/sample_prod.sqlite sqlite:///samples/sample_staging.sqlite
```

### CLI Terminal Output Example

```json
$ pii-shield inspect-db sqlite:///samples/sample_prod.sqlite
{
  "dialect": "sqlite",
  "topological_order": ["users", "orders", "support_tickets"],
  "fk_equivalence_groups": {
    "orders.customer_email": [
      "orders.customer_email",
      "support_tickets.reporter_email",
      "users.email"
    ]
  }
}

$ pii-shield scrub-db sqlite:///samples/sample_prod.sqlite sqlite:///samples/sample_staging.sqlite
{
  "source_dialect": "sqlite",
  "target_dialect": "sqlite",
  "mode": "synthetic",
  "tables_processed": ["users", "orders", "support_tickets"],
  "rows_copied": { "users": 2, "orders": 2, "support_tickets": 2 },
  "fk_groups_preserved": 3
}
```

---

## Contributing

We welcome contributions! Please read our [Contributing Guide](CONTRIBUTING.md) to learn how to add new national PII recognizers, write tests, and maintain our strict air-gap invariant.

---

## REST API Endpoints

- `GET /health` — Readiness probe and active detection backend (`presidio+spacy` or `regex+spacy`).
- `GET /api/v1/airgap-check` — Reports air-gap posture (`external_telemetry: false`, `outbound_network_calls: 0`).
- `POST /api/v1/scrub/text` — Scrub raw text or LLM prompts.
- `POST /api/v1/scrub/json` — Recursively scrub nested JSON payloads.
- `POST /api/v1/scrub/file` — Upload and scrub `.txt`, `.md`, `.csv`, `.json`, `.jsonl`, `.sql`, or `.pdf`.
- `POST /api/v1/db/inspect` — Inspect schema, topological order, FK groups, and auto-inferred PII rules.
- `POST /api/v1/db/anonymize` — Copy anonymized rows from `source_dsn` to `target_dsn` preserving all FKs.

---

## Open-Core Roadmap

- **Open-Source Core (Apache-2.0):** CLI, FastAPI engine, local Web UI, deterministic Faker/format-preserving anonymizer, SQLite/PostgreSQL FK-safe scrubber (including self-referencing FKs & `.sql` dump exports), 1-click Docker Compose.
- **Self-Hosted Enterprise Add-Ons (`app/enterprise/hooks.py`):** Clean `AuthProvider` and `AuditSink` protocol seams ready for team RBAC, tamper-evident compliance audit logs (SOC 2 / DPDP / GDPR), and SAML/OIDC SSO integration.
