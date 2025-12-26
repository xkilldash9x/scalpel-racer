import os
import sys
import stat
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call

# -- Add project root to path for direct import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import permissions

@pytest.fixture
def mock_sudo_env(monkeypatch):
    """Fixture to simulate running under sudo."""
    monkeypatch.setenv("SUDO_USER", "testuser")
    monkeypatch.setenv("SUDO_UID", "1001")
    monkeypatch.setenv("SUDO_GID", "1001")
    return "testuser", 1001, 1001

@pytest.fixture
def temp_project_dir(tmp_path):
    """Creates a temporary directory structure to simulate the project."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "file1.txt").touch()
    (project_dir / "subdir").mkdir()
    (project_dir / "subdir" / "file2.txt").touch()
    return project_dir

def test_restore_ownership_with_sudo(mock_sudo_env, temp_project_dir):
    """
    Verify that restore_ownership attempts to chown files and directories
    when running under a simulated sudo environment.
    """
    _, uid, gid = mock_sudo_env
    
    # The implementation uses rglob, not walk.
    # We also mock atexit so it doesn't run automatically
    with patch('os.lchown') as mock_lchown, \
         patch('atexit.register'), \
         patch('os.path.dirname', return_value=str(temp_project_dir)): # Patch dirname to return temp dir

        # Call the function without arguments
        permissions.restore_ownership()

        # Check that lchown was called for the directory and file
        expected_calls = [
            call(str(temp_project_dir), uid, gid),
            call(str(temp_project_dir / "file1.txt"), uid, gid),
            call(str(temp_project_dir / "subdir"), uid, gid),
            call(str(temp_project_dir / "subdir" / "file2.txt"), uid, gid),
        ]
        mock_lchown.assert_has_calls(expected_calls, any_order=True)
        # Verify call count matches total items
        assert mock_lchown.call_count == 4

def test_restore_ownership_without_sudo(temp_project_dir):
    """
    Verify that restore_ownership does nothing when not running under sudo.
    """
    # Ensure sudo environment variables are not set
    with patch.dict(os.environ, {}, clear=True):
        with patch('os.chown') as mock_chown, \
             patch('os.lchown') as mock_lchown, \
             patch('os.walk') as mock_walk, \
             patch('os.path.dirname', return_value=str(temp_project_dir)):
            
            permissions.restore_ownership()

            # Assertions
            mock_walk.assert_not_called()
            mock_chown.assert_not_called()
            mock_lchown.assert_not_called()