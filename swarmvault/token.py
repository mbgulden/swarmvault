import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Optional

from .types import CapabilityToken, TokenExpiredError, VaultError


class TokenEngine:
    """HMAC-based capability token generation and verification."""

    def __init__(self, secret_key: Optional[bytes] = None):
        if secret_key is None:
            self.secret_key = secrets.token_bytes(32)
        else:
            self.secret_key = secret_key

    def sign(self, payload: dict) -> str:
        """Generate HMAC-SHA256 signature for payload."""
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        signature = hmac.new(self.secret_key, payload_bytes, hashlib.sha256).hexdigest()
        return signature

    def verify(self, token: CapabilityToken) -> bool:
        """Verify signature and expiry of a token."""
        if time.time() > token.expires_at:
            raise TokenExpiredError("Token has expired")
        
        payload = {
            "token_id": token.token_id,
            "agent_id": token.agent_id,
            "scopes": token.scopes,
            "issued_at": token.issued_at,
            "expires_at": token.expires_at,
            "single_use": token.single_use,
            "metadata": token.metadata,
        }
        
        expected_signature = self.sign(payload)
        return hmac.compare_digest(expected_signature, token.signature)

    def encode(self, token: CapabilityToken) -> str:
        """Serialize token to compact string."""
        payload = {
            "token_id": token.token_id,
            "agent_id": token.agent_id,
            "scopes": token.scopes,
            "issued_at": token.issued_at,
            "expires_at": token.expires_at,
            "single_use": token.single_use,
            "metadata": token.metadata,
            "signature": token.signature,
        }
        json_bytes = json.dumps(payload).encode("utf-8")
        return base64.urlsafe_b64encode(json_bytes).decode("utf-8")

    def decode(self, encoded: str) -> CapabilityToken:
        """Deserialize and verify token."""
        try:
            json_bytes = base64.urlsafe_b64decode(encoded.encode("utf-8"))
            payload = json.loads(json_bytes.decode("utf-8"))
            
            token = CapabilityToken(
                token_id=payload["token_id"],
                agent_id=payload["agent_id"],
                scopes=payload["scopes"],
                issued_at=payload["issued_at"],
                expires_at=payload["expires_at"],
                single_use=payload["single_use"],
                signature=payload.get("signature", ""),
                metadata=payload.get("metadata", {}),
            )
            
            if not self.verify(token):
                raise VaultError("Invalid token signature")
            
            return token
        except (ValueError, KeyError, base64.binascii.Error) as e:
            raise VaultError(f"Invalid token format: {e}")
