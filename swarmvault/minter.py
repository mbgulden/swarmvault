import sqlite3
import time
import uuid
from pathlib import Path
from typing import List, Optional

from .token import TokenEngine
from .types import (
    CapabilityToken,
    InsufficientScopeError,
    TokenRequest,
    TokenRevokedError,
    VaultError,
)


class TokenMinter:
    """Mints scoped, time-bounded capability tokens."""

    def __init__(self, engine: TokenEngine, db_path: Optional[Path] = None):
        self.engine = engine
        self.db_path = db_path or ":memory:"
        self.conn = sqlite3.connect(self.db_path)
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS tokens (
                token_id TEXT PRIMARY KEY,
                agent_id TEXT,
                expires_at REAL,
                status TEXT
            )
            '''
        )
        self.conn.commit()

    def mint(self, request: TokenRequest) -> CapabilityToken:
        """Create new token."""
        token_id = str(uuid.uuid4())
        issued_at = time.time()
        expires_at = issued_at + request.ttl_seconds
        
        token = CapabilityToken(
            token_id=token_id,
            agent_id=request.agent_id,
            scopes=request.scopes,
            issued_at=issued_at,
            expires_at=expires_at,
            single_use=request.single_use,
            metadata=request.metadata or {},
        )
        
        payload = {
            "token_id": token.token_id,
            "agent_id": token.agent_id,
            "scopes": token.scopes,
            "issued_at": token.issued_at,
            "expires_at": token.expires_at,
            "single_use": token.single_use,
            "metadata": token.metadata,
        }
        token.signature = self.engine.sign(payload)
        
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO tokens (token_id, agent_id, expires_at, status) VALUES (?, ?, ?, ?)",
            (token_id, request.agent_id, expires_at, "active")
        )
        self.conn.commit()
        
        return token

    def revoke(self, token_id: str):
        """Revoke token."""
        cursor = self.conn.cursor()
        cursor.execute("UPDATE tokens SET status = 'revoked' WHERE token_id = ?", (token_id,))
        self.conn.commit()

    def _is_revoked(self, token_id: str) -> bool:
        cursor = self.conn.cursor()
        cursor.execute("SELECT status FROM tokens WHERE token_id = ?", (token_id,))
        row = cursor.fetchone()
        if row and row[0] == "revoked":
            return True
        return False
        
    def _is_consumed(self, token_id: str) -> bool:
        cursor = self.conn.cursor()
        cursor.execute("SELECT status FROM tokens WHERE token_id = ?", (token_id,))
        row = cursor.fetchone()
        if row and row[0] == "consumed":
            return True
        return False

    def check(self, token: CapabilityToken, required_scope: str) -> bool:
        """Verify token is valid and has required scope."""
        self.engine.verify(token)
        
        if self._is_revoked(token.token_id):
            raise TokenRevokedError("Token has been revoked")
            
        if self._is_consumed(token.token_id):
            raise VaultError("Single-use token has already been consumed")
            
        if required_scope not in token.scopes and "*" not in token.scopes:
            raise InsufficientScopeError(f"Token lacks required scope: {required_scope}")
            
        return True

    def consume(self, token: CapabilityToken):
        """Mark single-use token as consumed."""
        if not token.single_use:
            return
            
        self.check(token, "*")
        
        cursor = self.conn.cursor()
        cursor.execute("UPDATE tokens SET status = 'consumed' WHERE token_id = ?", (token.token_id,))
        self.conn.commit()

    def list_active(self, agent_id: Optional[str] = None) -> List[CapabilityToken]:
        """List active tokens (mock return of just IDs as full details aren't stored, returning partial tokens)."""
        # In a real app we'd serialize full tokens, but here we just return stubs to meet API 
        # or load them if they were stored fully. We'll return dummy tokens just to show they are active.
        cursor = self.conn.cursor()
        if agent_id:
            cursor.execute("SELECT token_id, agent_id, expires_at FROM tokens WHERE status = 'active' AND agent_id = ?", (agent_id,))
        else:
            cursor.execute("SELECT token_id, agent_id, expires_at FROM tokens WHERE status = 'active'")
            
        rows = cursor.fetchall()
        result = []
        for row in rows:
            result.append(CapabilityToken(
                token_id=row[0],
                agent_id=row[1],
                scopes=[],
                issued_at=0.0,
                expires_at=row[2],
                single_use=False
            ))
        return result
