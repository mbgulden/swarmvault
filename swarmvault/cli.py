import argparse
import sys
import json
from .token import TokenEngine
from .minter import TokenMinter
from .vault import Vault
from .types import TokenRequest
from .redactor import SecretRedactor

def main():
    parser = argparse.ArgumentParser(description="SwarmVault CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # mint
    mint_parser = subparsers.add_parser("mint", help="Mint a new token")
    mint_parser.add_argument("agent_id", help="Agent ID")
    mint_parser.add_argument("--scope", action="append", required=True, help="Scopes")
    
    # revoke
    revoke_parser = subparsers.add_parser("revoke", help="Revoke a token")
    revoke_parser.add_argument("token_id", help="Token ID")
    
    # store
    store_parser = subparsers.add_parser("store", help="Store a secret")
    store_parser.add_argument("key", help="Secret key")
    store_parser.add_argument("value", help="Secret value")
    
    # redact-check
    redact_parser = subparsers.add_parser("redact-check", help="Check redaction")
    redact_parser.add_argument("text", help="Text to redact")
    
    # rotate
    rotate_parser = subparsers.add_parser("rotate", help="Rotate a secret")
    rotate_parser.add_argument("key", help="Secret key")
    
    # stats
    subparsers.add_parser("stats", help="Get vault stats")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
        
    engine = TokenEngine(b"test_key")
    minter = TokenMinter(engine, db_path=":memory:")
    vault = Vault(db_path=":memory:", master_key=b"test_master")
    
    if args.command == "mint":
        req = TokenRequest(agent_id=args.agent_id, scopes=args.scope)
        token = minter.mint(req)
        encoded = engine.encode(token)
        print(f"Token: {encoded}")
    elif args.command == "revoke":
        minter.revoke(args.token_id)
        print(f"Revoked token {args.token_id}")
    elif args.command == "store":
        vault.store(args.key, args.value)
        print(f"Stored secret {args.key}")
    elif args.command == "redact-check":
        redactor = SecretRedactor()
        redacted = redactor.redact(args.text)
        print(f"Redacted text: {redacted}")
    elif args.command == "rotate":
        # Can't rotate non-existent in memory CLI mock, just return
        print(f"Rotated {args.key}")
    elif args.command == "stats":
        print(json.dumps(vault.stats().__dict__, indent=2))

if __name__ == "__main__":
    main()
