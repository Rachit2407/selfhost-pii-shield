# Contributing to Self-Hosted PII Shield

Thank you for your interest in contributing to **PII Shield**! This project is dedicated to providing enterprise engineering teams with a 100% air-gapped, privacy-preserving tool for local database anonymization and LLM prompt scrubbing.

---

## Non-Negotiable Core Invariant

> **Strict Air-Gap Guarantee:**
> PII Shield must NEVER introduce external telemetry, tracking, or outbound network calls.
> Any PR that attempts to fetch remote models at runtime, inject external CDN links (fonts, scripts) into the Web UI, or phone home will be rejected. All NLP models and checksum validators must operate completely offline.

---

## Local Development Setup

### 1. Clone & Setup Virtual Environment

```bash
git clone https://github.com/Rachit2407/selfhost-pii-shield.git
cd selfhost-pii-shield

# Create isolated virtual environment
python -m venv .venv

# Activate on Windows:
.\.venv\Scripts\activate
# Activate on Linux/macOS:
source .venv/bin/activate

# Install editable package with dev dependencies
pip install --upgrade pip
pip install -e ".[dev]"

# Pre-download the spaCy model locally (used offline thereafter)
python -m spacy download en_core_web_sm
```

### 2. Generate Demo Database & Run Tests

```bash
# Generate the multi-table synthetic SQLite sample database
python samples/create_sample_db.py

# Run the complete test suite
pytest -v
```

All 20 tests must pass before opening a Pull Request.

---

## How to Add a New PII Recognizer

New recognizers belong in [`app/engine/recognizers.py`](app/engine/recognizers.py).

1. **Define the Canonical Specification:**
   Add a `LocalPatternSpec` to `LOCAL_PATTERN_SPECS`:
   ```python
   LocalPatternSpec(
       entity_type="MY_COUNTRY_TAX_ID",
       pattern_name="tax_id_regex",
       regex=r"\b[0-9]{9}[A-Z]\b",
       score=0.85,
       context=("tax", "tin", "revenue"),
       validator=my_optional_checksum_function, # Optional pure-Python validator
       presidio_custom=True,
   )
   ```
2. **Add Checksum Validation (if applicable):**
   If the national ID or card uses a checksum (e.g. Luhn, Verhoeff, Mod-11), implement a pure-Python validation function with zero external dependencies to prevent false positives.
3. **Add Deterministic Replacement (if applicable):**
   In [`app/engine/deterministic.py`](app/engine/deterministic.py), add synthetic format-preserving generation logic for `MY_COUNTRY_TAX_ID`.
4. **Write Tests:**
   Add positive and negative unit test cases in [`tests/test_recognizers.py`](tests/test_recognizers.py).

---

## Pull Request Guidelines

1. **Branch Naming:**
   - `feat/add-brazil-cpf-recognizer`
   - `fix/mysql-foreign-key-ordering`
   - `docs/update-vpc-guide`
2. **Commit Messages:**
   Use Conventional Commits: `feat:`, `fix:`, `docs:`, `chore:`, `test:`.
3. **CI Passing:**
   GitHub Actions will automatically run `pytest -v` on Python 3.12 and verify `docker build .` across every PR.

---

## Open-Core Separation

- The **Open-Source Core** contains the CLI, FastAPI engine, Web UI, deterministic Faker anonymizer, SQLite/PostgreSQL FK-safe scrubber, and 1-click Docker setup under **Apache-2.0**.
- Enterprise extensions (SAML/SSO, team RBAC, immutable compliance audit log sinks) hook into [`app/enterprise/hooks.py`](app/enterprise/hooks.py). Pull requests extending core functionality should preserve these clean protocol seams.
