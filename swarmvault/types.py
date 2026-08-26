from dataclasses import dataclass, field
from typing import Dict, List, Optional


class VaultError(Exception):
    """Base exception for Vault errors."""
    pass


class TokenExpiredError(VaultError):
    """Raised when a token has expired."""
    pass


class TokenRevokedError(VaultError):
    """Raised when a token has been revoked."""
    pass


class InsufficientScopeError(VaultError):
    """Raised when a token does not have the required scope."""
    pass


@dataclass
class CapabilityToken:
    """A scoped, time-bounded capability token."""
    token_id: str
    agent_id: str
    scopes: List[str]
    issued_at: float
    expires_at: float
    single_use: bool
    signature: str = ""
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class TokenRequest:
    """Request to mint a new token."""
    agent_id: str
    scopes: List[str]
    ttl_seconds: int = 900
    single_use: bool = False
    metadata: Optional[Dict[str, str]] = None


@dataclass
class SecretEntry:
    """A secret stored in the vault."""
    key: str
    value: str
    created_at: float
    expires_at: float
    rotation_count: int
    last_rotated: float


@dataclass
class RotationPolicy:
    """Policy for automatic secret rotation."""
    auto_rotate: bool = True
    rotation_interval_seconds: int = 3600
    max_versions: int = 3


@dataclass
class RedactionPattern:
    """Pattern for automatic secret redaction."""
    name: str
    pattern: str
    replacement: str = "***REDACTED***"


@dataclass
class VaultStats:
    """Statistics for the vault."""
    total_secrets: int
    active_tokens: int
    revoked_tokens: int
    rotations_performed: int
