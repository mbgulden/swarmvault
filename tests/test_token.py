import time
import pytest
from swarmvault.token import TokenEngine
from swarmvault.types import CapabilityToken, TokenExpiredError

def test_sign_and_verify():
    """Test HMAC signing and verification."""
    engine = TokenEngine(b"secret")
    token = CapabilityToken(
        token_id="123", agent_id="agent1", scopes=["read"],
        issued_at=time.time(), expires_at=time.time() + 3600, single_use=False
    )
    payload = {
        "token_id": token.token_id, "agent_id": token.agent_id, "scopes": token.scopes,
        "issued_at": token.issued_at, "expires_at": token.expires_at, "single_use": token.single_use,
        "metadata": token.metadata
    }
    signature = engine.sign(payload)
    token.signature = signature
    
    assert engine.verify(token) is True

def test_verify_expired():
    """Test verification fails on expired token."""
    engine = TokenEngine()
    token = CapabilityToken(
        token_id="123", agent_id="agent1", scopes=["read"],
        issued_at=time.time() - 3600, expires_at=time.time() - 1800, single_use=False
    )
    with pytest.raises(TokenExpiredError):
        engine.verify(token)

def test_encode_decode():
    """Test token serialization."""
    engine = TokenEngine()
    token = CapabilityToken(
        token_id="123", agent_id="agent1", scopes=["read"],
        issued_at=time.time(), expires_at=time.time() + 3600, single_use=False
    )
    payload = {
        "token_id": token.token_id, "agent_id": token.agent_id, "scopes": token.scopes,
        "issued_at": token.issued_at, "expires_at": token.expires_at, "single_use": token.single_use,
        "metadata": token.metadata
    }
    token.signature = engine.sign(payload)
    
    encoded = engine.encode(token)
    decoded = engine.decode(encoded)
    
    assert decoded.token_id == token.token_id
    assert decoded.agent_id == token.agent_id
