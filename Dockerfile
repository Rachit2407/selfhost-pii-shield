# 100% Air-Gapped Ready Image for Self-Hosted PII Shield
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PII_SHIELD_AIRGAP_STRICT=true \
    PII_SHIELD_HOST=0.0.0.0 \
    PII_SHIELD_PORT=8080

WORKDIR /app

# Install runtime dependencies and bake spaCy English model at build time (zero runtime downloads).
COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install --upgrade pip \
    && pip install . \
    && python -m spacy download en_core_web_sm

COPY samples ./samples

RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
