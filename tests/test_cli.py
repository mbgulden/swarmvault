import subprocess
import sys

def test_cli_help():
    result = subprocess.run([sys.executable, "-m", "swarmvault", "--help"], capture_output=True, text=True)
    assert "SwarmVault CLI" in result.stdout

def test_cli_mint():
    result = subprocess.run([sys.executable, "-m", "swarmvault", "mint", "agent1", "--scope", "read"], capture_output=True, text=True)
    assert "Token:" in result.stdout
