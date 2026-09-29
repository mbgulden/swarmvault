# 🔐 SwarmVault

[![CI](https://github.com/mbgulden/swarmvault/actions/workflows/ci.yml/badge.svg)](https://github.com/mbgulden/swarmvault/actions)
[![PyPI version](https://img.shields.io/badge/pypi-v0.1.0-blue.svg)](https://pypi.org/project/swarmvault/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Zero-trust ephemeral capability broker and secret authority for AI agent swarms**  
> *Short-lived, HMAC-signed capability tokens with expiry, scopes, and single-use enforcement —
> plus an encrypted secret store, automatic secret redaction, and dynamic key rotation.*

---

## 💡 Why SwarmVault?

AI agent swarms share credentials, hand off tasks, and spawn sub-agents constantly.
Long-lived API keys copied into prompts are a breach waiting to happen. **SwarmVault** replaces
shared static credentials with **ephemeral, scoped, single-purpose tokens**:

- An agent gets a capability token good for exactly what it needs (`read:db_creds`, not `*`),
  expiring in minutes (default TTL: 15 minutes), revocable at any time.
- Secrets live in one store with per-secret TTLs and automatic rotation — agents never hold
  the master key.
- Anything that leaves the vault passes through the **redactor** first: API keys, bearer
  tokens, passwords, and connection strings are masked before they can leak into logs,
  prompts, or receipts.

No shared root keys. No immortal tokens. No plaintext secrets in stdout.

---

## 🏛️ How It Fits Together

```
                 ┌──────────────────────────────────────────────┐
                 │                  AI Agent Swarm              │
                 │        (agents request capabilities,         │
                 │         never the raw secrets)               │
                 └──────────────────────┬───────────────────────┘
                                        │
                              1. Request scoped token
                                        ▼
                 ┌──────────────────────────────────────────────┐
                 │                 TokenMinter                  │
                 │  - HMAC-SHA256 signed capability tokens      │
                 │  - scopes, TTL, single-use, revocation       │
                 │  - SQLite-backed token registry              │
                 └──────────────────────┬───────────────────────┘
                                        │
                              2. Present token, read secret
                                        ▼
                 ┌──────────────────────────────────────────────┐
                 │                    Vault                     │
                 │  - SQLite secret store, encrypted at rest    │
                 │  - per-secret TTLs, delete, list, stats      │
                 │  - rotate() generates fresh random values   │
                 └──────────────────────┬───────────────────────┘
                                        │
                              3. Rotate & redact
                                        ▼
          ┌─────────────────────┐                  ┌──────────────────────┐
          │  RotationManager    │                  │   SecretRedactor     │
          │ - rotation policies │                  │ - regex + exact-match│
          │ - schedules         │                  │   masking of keys,   │
          │ - audit history     │                  │   tokens, passwords  │
          └─────────────────────┘                  └──────────────────────┘
```

---

## 📦 Installation

```bash
pip install swarmvault
```

*Pure Python standard library at runtime — zero heavy dependencies.*

Requires Python 3.9+.

---

## 🚀 Quick Start (< 5 min)

### 1. Mint a scoped token for an agent

```bash
# Mint a token for agent1 with read scope
swarmvault mint agent1 --scope read --scope write

# Store a secret
swarmvault store db_password "s3cr3t-value"

# Check what the redactor catches in your logs
swarmvault redact-check "connecting with api_key=sk_live_abc123xyz789012345"

# Rotate a secret to a fresh random value
swarmvault rotate db_password

# Vault stats
swarmvault stats
```

> **Note:** the CLI is a demo harness — it runs against an in-memory vault with a throwaway
> key. For anything real, use the Python API with your own master key and a persistent `db_path`.

### 2. Python SDK: the full flow

```python
from swarmvault import (
    TokenEngine, TokenMinter, Vault,
    SecretRedactor, RotationManager,
    TokenRequest, RotationPolicy,
)

# --- 1. Set up the authority (once) ---
engine = TokenEngine()              # random 32-byte HMAC key (pass your own bytes to pin it)
minter = TokenMinter(engine, db_path="tokens.db")
vault = Vault(db_path="vault.db")   # random 32-byte master key (pass your own to pin it)

# --- 2. Store a secret with a TTL ---
vault.store("db_password", "s3cr3t-value", ttl_seconds=3600)

# --- 3. Mint a least-privilege token for an agent ---
token = minter.mint(TokenRequest(
    agent_id="agent-42",
    scopes=["read:db_password"],     # least privilege: this key only
    ttl_seconds=900,                 # 15 minutes, then dead
    single_use=False,
))

# --- 4. Agent redeems the token for the secret ---
value = vault.retrieve("db_password", token=token, minter=minter)
print(value)  # s3cr3t-value

# --- 5. Revoke when the job is done ---
minter.revoke(token.token_id)

# --- 6. Redact anything before it leaves the vault ---
redactor = SecretRedactor()
redactor.add_secret(value, label="db_password")   # exact-match masking too
safe_log = redactor.redact(f"connected, pw={value}")
print(safe_log)  # connected, pw=***REDACTED_db_password***
```

### 3. Automatic rotation

```python
vault = Vault(db_path="vault.db")
vault.store("stripe_key", "sk_live_old")

manager = RotationManager(vault, RotationPolicy(auto_rotate=True))
manager.schedule_rotation("stripe_key", interval_seconds=3600)  # hourly

rotated = manager.check_and_rotate()   # -> ["stripe_key"] when due
print(manager.rotation_history("stripe_key"))  # audit trail of rotations
```

`vault.rotate(key)` replaces the value with a fresh `secrets.token_urlsafe(32)` value,
bumps `rotation_count`, and preserves the original TTL.

---

## 🧰 Component Reference

| Component | Module | What it does |
|---|---|---|
| `TokenEngine` | `swarmvault/token.py` | HMAC-SHA256 sign/verify, base64url encode/decode of tokens. Pass `secret_key` bytes to pin the signing key; otherwise a random 32-byte key is generated. |
| `TokenMinter` | `swarmvault/minter.py` | Mints `CapabilityToken`s (UUID id, scopes, `issued_at`/`expires_at`, `single_use`, metadata). SQLite registry tracks `active` / `revoked` / `consumed`. `check(token, scope)` enforces expiry, revocation, single-use consumption, and scope match (`*` wildcard supported). |
| `Vault` | `swarmvault/vault.py` | SQLite secret store. Values are XOR-masked with the master key and base64-encoded at rest. Supports per-secret TTLs, expiry enforcement on read, `delete`, `list_keys`, `stats`, and `rotate`. |
| `SecretRedactor` | `swarmvault/redactor.py` | Built-in regex patterns for API keys, bearer tokens, passwords, and DB connection strings (password portion masked, host preserved). `add_pattern()` registers custom regexes; `add_secret()` registers exact values to mask. |
| `RotationManager` | `swarmvault/rotation.py` | Schedules rotations per key, rotates when due, and keeps a `rotation_history` audit log (`success`/`failed`). Disabled entirely when `policy.auto_rotate=False`. |
| CLI | `swarmvault/cli.py` | `swarmvault mint|revoke|store|redact-check|rotate|stats`. Entry point: `swarmvault = "swarmvault.cli:main"`. |

### Error types

All exceptions derive from `VaultError`: `TokenExpiredError`, `TokenRevokedError`, `InsufficientScopeError`.

---

## ⚠️ Security Notes

Be honest about what this is:

- **At-rest "encryption" is XOR masking**, not authenticated encryption. It stops casual
  reads of the SQLite file; it is not AES-GCM. If your threat model needs real encryption
  at rest, wrap the `db_path` with filesystem-level encryption or swap the cipher.
- **Tokens are bearer tokens** — anyone holding the encoded string can redeem it until it
  expires, is revoked, or is consumed (single-use). Keep TTLs short and transport tokens
  over encrypted channels.
- **Signing key and master key are the crown jewels.** `TokenEngine()` and `Vault()` generate
  random keys when you don't pass one — that's fine for a session, but for persistence you
  must supply stable keys (e.g. from your KMS / environment) and keep them out of code.
- The CLI's built-in demo keys are **not real secrets** — they're fixed placeholder bytes for
  the in-memory demo path only. Never treat CLI output as production behavior.

---

## 🔌 Swarm Ecosystem

SwarmVault is part of the **Prismatic / Swarm Primitives** family for autonomous agent swarms:

- 🔐 **SwarmVault**: Ephemeral capability broker & secret authority (this package).
- 🛡️ **SwarmProof**: Truth Oracle, evidence ledgers, and anti-hallucination gates.
- 🔒 **SwarmLock**: Tokenized, non-blocking distributed advisory locks.
- ⏱️ **SwarmCron**: Native high-precision background cron scheduling.

---

## 🧪 Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
ruff check .
```

---

## 📄 License

MIT © Michael Gulden — see [LICENSE](LICENSE).
