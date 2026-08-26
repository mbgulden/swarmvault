import pytest
from swarmvault.vault import Vault
from swarmvault.types import VaultError

def test_store_and_retrieve():
    vault = Vault(master_key=b"testkey")
    vault.store("db_pass", "secret123")
    
    val = vault.retrieve("db_pass")
    assert val == "secret123"

def test_retrieve_missing():
    vault = Vault()
    with pytest.raises(VaultError):
        vault.retrieve("nonexistent")

def test_rotate_secret():
    vault = Vault()
    vault.store("api_key", "old_key")
    entry = vault.rotate("api_key")
    
    assert entry.key == "api_key"
    assert vault.retrieve("api_key") != "old_key"
    
def test_delete_secret():
    vault = Vault()
    vault.store("test_key", "val")
    vault.delete("test_key")
    with pytest.raises(VaultError):
        vault.retrieve("test_key")
