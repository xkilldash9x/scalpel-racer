# permissions.py
"""
Handles automatic permission restoration for sudo-executed scripts.
This module registers an atexit handler to restore file ownership
to the original user (SUDO_UID/SUDO_GID) upon script termination.
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
    # These variables are only present if run via sudo
    sudo_uid = os.environ.get('SUDO_UID')
    sudo_gid = os.environ.get('SUDO_GID')

    # Only run if we are effectively root and have a sudo user to revert to
    if sudo_uid and sudo_gid:
        try:
            uid = int(sudo_uid)
            gid = int(sudo_gid)
            
            # Use the directory where this script resides
            project_dir = os.path.dirname(os.path.abspath(__file__))
            
            # Walk the directory and fix everything
            # We silently ignore errors for special files (sockets, etc.)
            for root, dirs, files in os.walk(project_dir):
                # Fix directory itself
                try: 
                    os.chown(root, uid, gid)
                except OSError: 
                    pass

                for name in files:
                    filepath = os.path.join(root, name)
                    try:
                        os.chown(filepath, uid, gid)
                    except OSError:
                        pass 

            # Feedback so the user knows why the script hangs for a split second at the end
            print(f"[*] Ownership restored to user ID {uid}.")

        except Exception as e:
            print(f"[!] Failed to restore ownership: {e}")

# Automatically register the cleanup when this module is imported
atexit.register(restore_ownership)

if __name__ == "__main__":
    restore_ownership()
    sys.exit(0)