# PII Shield — Public Launch & Distribution Kit

This kit contains ready-to-publish launch copy for LinkedIn, Reddit, Twitter/X, Hacker News, and your technical resume.

---

## 1. GitHub Release Notes (`v0.1.0`)

**Title:** `v0.1.0: 100% Air-Gapped Local PII Redactor & Synthetic DB Anonymizer`

```markdown
## Release v0.1.0: 100% Air-Gapped Local PII Redactor & Synthetic DB Anonymizer

### Highlights
- **100% Air-Gapped Operation:** Pre-baked spaCy model (`en_core_web_sm`), zero external telemetry, zero outbound API calls, zero external CDN imports in the Web UI.
- **FK-Preserving Relational DB Anonymizer:** Introspects PK/FK schema graphs via SQLAlchemy, groups connected columns via Union-Find equivalence classes, topologically orders parent-before-child tables, handles self-referencing FKs, and streams rows in chunks of 5,000 to prevent OOM.
- **Deterministic Keyed Replacement:** Seeded via `HMAC-SHA256(PII_SHIELD_SALT, type:normalized_value)` so identical PII maps identically across runs, tables, and documents without plaintext lookup tables.
- **Native Indian + Global PII Support:** High-precision recognizers for `IN_PAN`, `IN_AADHAAR` (Verhoeff checksum validated), `IN_UPI`, `CREDIT_CARD` (Luhn checksum validated), `SECRET_TOKEN` (AWS `AKIA...`, JWTs, OpenAI `sk-...`, GitHub PATs), `EMAIL_ADDRESS`, `PHONE_NUMBER`, `IP_ADDRESS`, `US_SSN`.
- **Connectors:** SQLite, PostgreSQL, SQL dumps (`.sql`), newline-delimited JSON (`.jsonl`), `.txt`, `.md`, `.csv`, `.json`, and `.pdf`.
- **FastAPI + Web UI + CLI:** 7 REST endpoints, lightweight dark-mode Web UI, and Typer CLI (`pii-shield`).

### 1-Click Docker Quickstart
```bash
git clone https://github.com/Rachit2407/selfhost-pii-shield.git
cd selfhost-pii-shield
docker compose up --build
```
Access the local Web UI at `http://localhost:8080`.
```

---

## 2. LinkedIn Launch Post

**Target Audience:** Engineering Leads, Founders, Data Privacy Officers, DevSecOps Engineers.

```text
Most engineering teams face an uncomfortable reality:

To test staging environments or build AI features with LLMs, developers copy production databases or dump customer logs. Suddenly, real customer emails, phone numbers, PAN, Aadhaar, and credit cards are sitting in staging environments or sent to third-party AI APIs.

Commercial synthetic data tools like Tonic.ai cost upwards of $20,000/year. Meanwhile, cloud-hosted PII redactors require you to upload your sensitive data to yet another third party—violating the India DPDP Act and EU GDPR.

I built and open-sourced PII Shield: a 1-click Dockerized PII redactor and relational database anonymizer that runs 100% locally inside your private VPC with ZERO outbound network calls.

Key engineering highlights:
1. 100% Air-Gapped Capable: The NLP model (en_core_web_sm) is pre-baked into the container. Zero telemetry, zero outbound API calls, and zero external CDN links in the Web UI.
2. Deterministic Keyed Replacement: Uses HMAC-SHA256 with a private salt so that identical PII maps identically across multi-table foreign keys and LLM prompts without storing a plaintext lookup table.
3. Preserves Database Foreign Keys: Uses Union-Find equivalence classes and topological sorting so users -> orders -> support_tickets joins never break, even across self-referencing tables and streaming batch migrations.
4. Native Indian + Global PII: Built-in Verhoeff checksum validation for 12-digit Aadhaar, Luhn validation for cards, Indian PAN, UPI VPAs, plus leaked API keys (AWS, OpenAI, JWTs).

Stack: Python 3.12, FastAPI, Microsoft Presidio Analyzer, SQLAlchemy, Docker Compose.

The project is completely open source under Apache 2.0:
GitHub: https://github.com/Rachit2407/selfhost-pii-shield

I'd love feedback from backend engineers and data teams!

#python #opensource #dataprivacy #dpdp #fastapi #cybersecurity #docker #machinelearning
```

---

## 3. Reddit Post (for `r/selfhosted`, `r/LocalLLaMA`, `r/Python`)

**Title:** `I built PII Shield — an open-source, 100% air-gapped DB anonymizer & LLM prompt sanitizer with zero outbound calls`

```text
Hey everyone,

Whenever teams need to build staging databases or feed customer incident tickets into local LLMs (Ollama / vLLM) or external APIs, they run into the same problem: scrubbing PII without breaking relational foreign keys or trusting a third-party cloud.

I built PII Shield to solve this locally:
https://github.com/Rachit2407/selfhost-pii-shield

### What it does:
1. Relational DB Anonymizer (PostgreSQL / SQLite):
   - Introspects the schema via SQLAlchemy and groups connected PK/FK columns into equivalence classes using Union-Find.
   - Topologically sorts parent-before-child tables (and orders self-referencing tables like employee-manager hierarchies).
   - Generates deterministic replacements so `users.email` and `orders.customer_email` match identically without storing plaintext mapping files.
   - Streams in chunks of 5,000 rows to keep memory footprint flat.

2. Document & LLM Prompt Sanitizer:
   - Scrubs `.txt`, `.md`, `.csv`, `.json`, `.jsonl`, `.sql` dumps (replaces values in `INSERT` statements while preserving DDL), and `.pdf`.
   - Native recognition for Indian PAN, Aadhaar (with full Verhoeff checksum validation to eliminate false positives), UPI handles, payment cards (Luhn validated), leaked API keys/JWTs, emails, and phone numbers.

3. Strict Air-Gap Architecture:
   - spaCy's `en_core_web_sm` is baked into the Docker image at build time (zero downloads on startup).
   - The Web UI uses local vanilla HTML/CSS/JS with zero external CDN scripts or Google Fonts.
   - We even include a unit test that monkeypatches `socket.connect` to assert that zero outbound network sockets are opened during initialization and scrubbing.

### 1-Click Run:
```bash
git clone https://github.com/Rachit2407/selfhost-pii-shield.git
cd selfhost-pii-shield
docker compose up --build
```
Web UI runs locally at `http://localhost:8080`.

Repo: https://github.com/Rachit2407/selfhost-pii-shield
License: Apache 2.0

Feedback, issues, and PRs for additional country-specific recognizers are very welcome!
```

---

## 4. Twitter / X Thread

**Tweet 1:**
> Stop pasting customer data into LLMs or copying unmasked production DBs into staging.
> 
> I built PII Shield: an open-source, 1-click Dockerized PII redactor & database anonymizer that runs 100% locally in your VPC with zero outbound calls.
> 
> github.com/Rachit2407/selfhost-pii-shield 🧵👇

**Tweet 2:**
> Why not existing tools?
> - SaaS redactors require sending sensitive data to external servers.
> - Enterprise synthetic data platforms cost $20k+/yr.
> - Naive regex masking breaks foreign keys and relational database joins.

**Tweet 3:**
> How PII Shield preserves foreign keys:
> 1. Introspects PK/FK graphs via SQLAlchemy
> 2. Uses Union-Find to group connected keys into equivalence classes
> 3. Derives replacement seeds via HMAC-SHA256(salt, entity:value)
> 4. Topologically sorts tables so parent rows insert before child rows

**Tweet 4:**
> Built-in support for:
> - Aadhaar (Verhoeff checksum verified)
> - Indian PAN & UPI VPAs
> - Credit Cards (Luhn algorithm verified)
> - Leaked API tokens (AWS AKIA, OpenAI sk-, JWTs, GitHub PATs)
> - Emails, Phone Numbers, IPs, Names

**Tweet 5:**
> Runs 100% air-gapped. The NLP model is pre-baked in the Docker container, and the Web UI has zero external CDN dependencies.
> 
> Check out the repo and leave a star ⭐
> https://github.com/Rachit2407/selfhost-pii-shield

---

## 5. Resume / Portfolio Bullet Point

**Rachit | Final-Year B.Tech CSE**
- **PII Shield (Open-Core Air-Gapped Database & Document Anonymizer)** | *Python, FastAPI, Microsoft Presidio, SQLAlchemy, Docker*
  - Designed and built a 100% air-gapped PII redactor and relational database anonymizer deployed via 1-click Docker Compose with zero external network egress.
  - Implemented schema introspection using Union-Find equivalence classes and Kahn's topological sorting, guaranteeing 100% referential integrity across multi-table foreign keys and self-referencing schemas.
  - Engineered deterministic HMAC-SHA256 salted Faker generators and pure-Python checksum validation engines for Indian (Aadhaar Verhoeff, PAN, UPI) and global (Luhn credit cards, JWT/API keys) entities.
