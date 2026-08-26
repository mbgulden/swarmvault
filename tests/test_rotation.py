import time
from swarmvault.vault import Vault
from swarmvault.rotation import RotationManager
from swarmvault.types import RotationPolicy

def test_check_and_rotate():
    vault = Vault()
    vault.store("test_key", "val")
    
    policy = RotationPolicy(auto_rotate=True)
    manager = RotationManager(vault, policy)
    
    # Schedule to rotate immediately
    manager.schedule_rotation("test_key", -1)
    
    rotated = manager.check_and_rotate()
    assert "test_key" in rotated
    
    hist = manager.rotation_history("test_key")
    assert len(hist) == 1
    assert hist[0]["status"] == "success"
