"""Protocol interfaces for self-hosted enterprise add-ons (RBAC, SAML/SSO, Audit Logs).

Open-source deployments use the default open-core no-auth provider and optional
local metadata-only audit sink. Paid enterprise licenses can swap in SAML/OIDC
RBAC and immutable SIEM audit sinks without modifying core scrubbing routes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class AuditEvent:
    """Metadata-only compliance audit record (must NEVER contain raw PII)."""

    action: str
    backend: str
    findings_count: int
    entity_counts: dict[str, int] = field(default_factory=dict)
    actor: str = "local-user"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class AuthProvider(Protocol):
    """Extension hook for SAML/OIDC SSO & team RBAC in enterprise deployments."""

    def authorize(self, token: str | None, required_role: str = "operator") -> str:
        """Validate caller credentials and return actor identity."""


class AuditSink(Protocol):
    """Extension hook for tamper-evident compliance audit logging."""

    def record(self, event: AuditEvent) -> None:
        """Persist or forward a metadata-only audit event."""


class OpenCoreAuthProvider:
    """Default open-source provider for single-tenant/air-gapped VPC containers."""

    def authorize(self, token: str | None, required_role: str = "operator") -> str:
        _ = (token, required_role)
        return "local-operator"


class LocalJsonlAuditSink:
    """Optional local JSONL metadata audit sink (no-op if audit_log_path is None)."""

    def __init__(self, audit_log_path: Path | None = None) -> None:
        self._path = audit_log_path

    def record(self, event: AuditEvent) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")
