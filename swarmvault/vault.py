import base64
import secrets
import sqlite3
import time
from itertools import cycle
from pathlib import Path
from typing import List, Optional

from .types import CapabilityToken, SecretEntry, VaultStats, VaultError
from .minter import TokenMinter
from .token import TokenEngine

def _xor_crypt(data: bytes, key: bytes) -> bytes:
    """Simple XOR cipher for 'encryption at rest'."""
    return bytes(a ^ b for a, b in zip(data, cycle(key)))

class Vault:
    """Main secret store."""

    def __init__(self, db_path: Optional[Path] = None, master_key: Optional[bytes] = None):
        self.db_path = db_path or ":memory:"
        self.master_key = master_key or secrets.token_bytes(32)
        self.conn = sqlite3.connect(self.db_path)
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS secrets (
                key TEXT PRIMARY KEY,
                value TEXT,
                created_at REAL,
                expires_at REAL,
                rotation_count INTEGER,
                last_rotated REAL
            )
            '''
        )
        self.conn.commit()

    def store(self, key: str, value: str, ttl_seconds: Optional[int] = None):
        """Encrypt and store secret."""
        encrypted_value = base64.b64encode(_xor_crypt(value.encode('utf-8'), self.master_key)).decode('utf-8')
        now = time.time()
        expires_at = now + ttl_seconds if ttl_seconds else 0.0
        
        cursor = self.conn.cursor()
        cursor.execute(
            '''
            INSERT INTO secrets (key, value, created_at, expires_at, rotation_count, last_rotated)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value=excluded.value,
                expires_at=excluded.expires_at,
                rotation_count=rotation_count + 1,
                last_rotated=excluded.created_at
            ''',
            (key, encrypted_value, now, expires_at, 0, now)
        )
        self.conn.commit()

    def retrieve(self, key: str, token: Optional[CapabilityToken] = None, minter: Optional[TokenMinter] = None) -> str:
        """Retrieve with optional token auth."""
        if token and minter:
            minter.check(token, f"read:{key}")
            
        cursor = self.conn.cursor()
        cursor.execute("SELECT value, expires_at FROM secrets WHERE key = ?", (key,))
        row = cursor.fetchone()
        
        if not row:
            raise VaultError(f"Secret not found: {key}")
            
        encrypted_value, expires_at = row
        
        if expires_at > 0.0 and time.time() > expires_at:
            raise VaultError(f"Secret expired: {key}")
            
        decrypted_value = _xor_crypt(base64.b64decode(encrypted_value.encode('utf-8')), self.master_key).decode('utf-8')
        return decrypted_value

    def rotate(self, key: str) -> SecretEntry:
        """Rotate secret value (generates a new random value)."""
        new_value = secrets.token_urlsafe(32)
        
        cursor = self.conn.cursor()
        cursor.execute("SELECT expires_at, created_at FROM secrets WHERE key = ?", (key,))
        row = cursor.fetchone()
        if not row:
            raise VaultError(f"Secret not found: {key}")
            
        expires_at, created_at = row
        ttl = expires_at - created_at if expires_at > 0 else None
        
        self.store(key, new_value, int(ttl) if ttl else None)
        
        cursor.execute("SELECT * FROM secrets WHERE key = ?", (key,))
        row = cursor.fetchone()
        
        return SecretEntry(
            key=row[0],
            value="***ENCRYPTED***",
            created_at=row[2],
            expires_at=row[3],
            rotation_count=row[4],
            last_rotated=row[5]
        )

    def delete(self, key: str):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM secrets WHERE key = ?", (key,))
        self.conn.commit()

    def list_keys(self) -> List[str]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT key FROM secrets")
        return [row[0] for row in cursor.fetchall()]

    def stats(self) -> VaultStats:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM secrets")
        total_secrets = cursor.fetchone()[0]
        
        cursor.execute("SELECT SUM(rotation_count) FROM secrets")
        rotations = cursor.fetchone()[0] or 0
        
        # We don't have token stats in the vault DB directly unless they share DB, 
        # but returning basic stats.
        return VaultStats(
            total_secrets=total_secrets,
            active_tokens=0,
            revoked_tokens=0,
            rotations_performed=rotations
        )
