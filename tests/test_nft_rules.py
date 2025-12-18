import pytest
import subprocess
import os
import time
import sys
import re

# Ensure we can import modules from the current directory
sys.path.append(os.getcwd())

from packet_controller import PacketController, NFQUEUE_AVAILABLE

# Skip this test if we aren't root, because we can't touch nftables otherwise
@pytest.mark.skipif(os.geteuid() != 0, reason="This test requires sudo (root) to modify kernel rules.")
@pytest.mark.skipif(not NFQUEUE_AVAILABLE, reason="NetfilterQueue libraries not found.")
def test_nftables_lifecycle():
    """
    Integration Test:
    1. Starts PacketController (creates nftables rules).
    2. Verifies rules exist in the kernel.
    3. Stops PacketController (deletes rules).
    4. Verifies rules are gone.
    """
    
    # Configuration matches what the app uses
    TABLE_NAME = "scalpel_racer_ctx"
    TARGET_IP = "127.0.0.1"
    TARGET_PORT = 12345
    SRC_PORT = 54321
    
    print(f"\n[TEST] Initializing PacketController for {TABLE_NAME}...")
    pc = PacketController(TARGET_IP, TARGET_PORT, SRC_PORT)
    
    # 0. Pre-clean (just in case a previous run crashed hard)
    subprocess.call(["nft", "delete", "table", "ip", TABLE_NAME], 
                    stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    try:
        # 1. Start the Controller (Mocking "Application Start")
        pc.start()
        
        # Give the kernel a tiny fraction of a second to register the change
        time.sleep(0.1)

        # 2. VERIFY: Check if the table exists
        print("[TEST] Verifying rules exist...")
        cmd = ["nft", "list", "table", "ip", TABLE_NAME]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Assertions
        assert result.returncode == 0, f"FAILED: Table '{TABLE_NAME}' was not created!"
        assert "chain output_hook" in result.stdout, "FAILED: Chain 'output_hook' missing."
        
        # [FIX] Robust check for queue number (handles "queue num 99" vs "queue to 99")
        # We check if either variation exists in the output
        queue_pattern = re.compile(rf"queue (num|to) {pc.queue_num}")
        assert queue_pattern.search(result.stdout), f"FAILED: NFQueue rule for {pc.queue_num} missing. Output:\n{result.stdout}"
        
        print(f"[PASS] Table '{TABLE_NAME}' found with correct rules.")

    except Exception as e:
        pytest.fail(f"An exception occurred during the test: {e}")

    finally:
        # 3. Stop the Controller (Mocking "Application Stop")
        print("[TEST] Stopping PacketController...")
        pc.stop()

    # 4. VERIFY: Check if the table is gone
    print("[TEST] Verifying rules are deleted...")
    cmd = ["nft", "list", "table", "ip", TABLE_NAME]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # The command SHOULD fail (return non-zero) if the table is gone
    assert result.returncode != 0, f"FAILED: Table '{TABLE_NAME}' still exists after stop!"
    print("[PASS] Table successfully removed.")

if __name__ == "__main__":
    # Allow running directly with python3 test_nft_rules.py
    sys.exit(pytest.main(["-v", "-s", __file__]))