import sqlite3
import time
from typing import List

from .types import RotationPolicy
from .vault import Vault


class RotationManager:
    """Manages automatic secret rotation."""

    def __init__(self, vault: Vault, policy: RotationPolicy):
        self.vault = vault
        self.policy = policy
        self.conn = sqlite3.connect(self.vault.db_path)
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS rotation_schedule (
                key TEXT PRIMARY KEY,
                interval_seconds INTEGER,
                next_rotation REAL
            )
            '''
        )
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS rotation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT,
                rotated_at REAL,
                status TEXT
            )
            '''
        )
        self.conn.commit()

    def check_and_rotate(self) -> List[str]:
        """Rotate expired secrets, return rotated keys."""
        if not self.policy.auto_rotate:
            return []
            
        now = time.time()
        cursor = self.conn.cursor()
        
        cursor.execute("SELECT key, interval_seconds FROM rotation_schedule WHERE next_rotation <= ?", (now,))
        to_rotate = cursor.fetchall()
        
        rotated_keys = []
        for key, interval in to_rotate:
            try:
                self.vault.rotate(key)
                next_rot = now + interval
                
                cursor.execute("UPDATE rotation_schedule SET next_rotation = ? WHERE key = ?", (next_rot, key))
                cursor.execute("INSERT INTO rotation_history (key, rotated_at, status) VALUES (?, ?, ?)", (key, now, "success"))
                self.conn.commit()
                rotated_keys.append(key)
            except Exception:
                cursor.execute("INSERT INTO rotation_history (key, rotated_at, status) VALUES (?, ?, ?)", (key, now, "failed"))
                self.conn.commit()
                
        return rotated_keys

    def schedule_rotation(self, key: str, interval_seconds: int):
        """Schedule rotation."""
        now = time.time()
        next_rotation = now + interval_seconds
        
        cursor = self.conn.cursor()
        cursor.execute(
            '''
            INSERT INTO rotation_schedule (key, interval_seconds, next_rotation)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                interval_seconds=excluded.interval_seconds,
                next_rotation=excluded.next_rotation
            ''',
            (key, interval_seconds, next_rotation)
        )
        self.conn.commit()

    def rotation_history(self, key: str) -> List[dict]:
        """Rotation audit log."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT rotated_at, status FROM rotation_history WHERE key = ? ORDER BY rotated_at DESC", (key,))
        rows = cursor.fetchall()
        return [{"rotated_at": row[0], "status": row[1]} for row in rows]
