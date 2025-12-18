# permissions.py
"""
Handles automatic permission restoration for sudo-executed scripts.
"""

import os
import atexit 
import sys 

def restore_ownership(): 
    """
    Called on exit. Checks if the script was run via sudo.
    If so, recursively chowns the current directory back to the
    original user (SUDO_UID/SUDO_GID) to prevent permission lockouts.
    """
    sudo_uid = os.environ.get('SUDO_UID')
    sudo_gid = os.environ.get('SUDO_GID')

    if sudo_uid and sudo_gid:
        try:
            uid = int(sudo_uid)
            gid = int(sudo_gid)
            project_dir = os.path.dirname(os.path.abspath(__file__))
            
            for root, dirs, files in os.walk(project_dir):
                try: os.chown(root, uid, gid)
                except OSError: pass
                for name in files:
                    filepath = os.path.join(root, name)
                    try: os.chown(filepath, uid, gid)
                    except OSError: pass

            print(f"[*] Ownership restored to user ID {uid}.")
        except Exception as e:
            print(f"[!] Failed to restore ownership: {e}")

atexit.register(restore_ownership)

if __name__ == "__main__":
    restore_ownership()
    sys.exit(0)
