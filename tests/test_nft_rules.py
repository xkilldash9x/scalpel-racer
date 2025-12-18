import pytest
import subprocess
import os
import time
import sys
import re
sys.path.append(os.getcwd())
from packet_controller import PacketController, NFQUEUE_AVAILABLE

@pytest.mark.skipif(os.geteuid() != 0, reason="Requires sudo.")
@pytest.mark.skipif(not NFQUEUE_AVAILABLE, reason="NetfilterQueue missing.")
def test_nftables_lifecycle():
    TABLE_NAME = "scalpel_racer_ctx"
    pc = PacketController("127.0.0.1", 12345, 54321)
    subprocess.call(["nft", "delete", "table", "ip", TABLE_NAME], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    try:
        pc.start(); time.sleep(0.1)
        cmd = ["nft", "list", "table", "ip", TABLE_NAME]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0
        assert "chain output_hook" in result.stdout
    finally:
        pc.stop()
    result = subprocess.run(["nft", "list", "table", "ip", TABLE_NAME], capture_output=True, text=True)
    assert result.returncode != 0
