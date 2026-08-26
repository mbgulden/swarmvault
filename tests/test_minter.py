import pytest
from swarmvault.token import TokenEngine
from swarmvault.minter import TokenMinter
from swarmvault.types import TokenRequest, TokenRevokedError, InsufficientScopeError, VaultError

def test_mint_and_check():
    engine = TokenEngine()
    minter = TokenMinter(engine)
    req = TokenRequest(agent_id="agent1", scopes=["read", "write"])
    token = minter.mint(req)
    
    assert minter.check(token, "read") is True
    with pytest.raises(InsufficientScopeError):
        minter.check(token, "admin")

def test_revoke_token():
    engine = TokenEngine()
    minter = TokenMinter(engine)
    req = TokenRequest(agent_id="agent1", scopes=["read"])
    token = minter.mint(req)
    
    minter.revoke(token.token_id)
    with pytest.raises(TokenRevokedError):
        minter.check(token, "read")

def test_single_use_token():
    engine = TokenEngine()
    minter = TokenMinter(engine)
    req = TokenRequest(agent_id="agent1", scopes=["*"], single_use=True)
    token = minter.mint(req)
    
    minter.consume(token)
    with pytest.raises(VaultError):
        minter.check(token, "*")
