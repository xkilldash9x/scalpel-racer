package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadOrCreateCA_SymlinkAttack verifies that we do not follow symlinks
// when writing certificates, preventing arbitrary file overwrite attacks.
func TestLoadOrCreateCA_SymlinkAttack(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Create a "victim" file that simulates /etc/shadow or similar
	victimFile := filepath.Join(tmpDir, "victim_secret.txt")
	secretData := []byte("superexclusivesecret")
	if err := os.WriteFile(victimFile, secretData, 0600); err != nil {
		t.Fatal(err)
	}

	// 2. Create the cert directory
	certDir := filepath.Join(tmpDir, "certs")
	if err := os.Mkdir(certDir, 0700); err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(certDir, "ca.pem")
	keyPath := filepath.Join(certDir, "ca.key")

	// 3. Create a symlink at certPath pointing to victimFile
	// Note: We only link certPath. keyPath will be missing, triggering regeneration.
	if err := os.Symlink(victimFile, certPath); err != nil {
		t.Fatal(err)
	}

	// 4. Run LoadOrCreateCA
	// This should regenerate the certs because keyPath is missing.
	// IT MUST NOT overwrite victimFile.
	_, err := LoadOrCreateCA(certPath, keyPath)
	if err != nil {
		t.Logf("LoadOrCreateCA returned error (acceptable): %v", err)
	}

	// 5. Check if victimFile is intact
	content, err := os.ReadFile(victimFile)
	if err != nil {
		t.Fatal(err)
	}

	if string(content) != string(secretData) {
		t.Fatalf("SECURITY VULNERABILITY: Target file was overwritten! Content: %s", string(content))
	}

	// 6. Verify that certPath is now a real file (not a symlink) or at least the certs were generated safely
	// If we successfully wrote the cert, certPath should now contain a certificate.
	// If LoadOrCreateCA succeeded, we expect certPath to be a file with a cert.
	fi, err := os.Lstat(certPath)
	if err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			// If it's still a symlink, and we didn't overwrite target...
			// Wait, if it's still a symlink, os.WriteFile would have written to target.
			// Unless os.WriteFile failed?
			t.Log("certPath is still a symlink.")
		} else {
			t.Log("certPath is now a regular file.")
		}
	}
}
