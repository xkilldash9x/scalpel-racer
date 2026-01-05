package proxy

import (
	"crypto/x509"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestCertGeneration_ConcurrencyHammer simulates a high-load environment where
// hundreds of concurrent connections request certificates simultaneously.
// This validates the thread safety of the shared serverKey optimization.
func TestCertGeneration_ConcurrencyHammer(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	keyPath := filepath.Join(tmpDir, "ca.key")

	// Setup CA
	ca, err := LoadOrCreateCA(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Shared key setup
	serverKey, err := GenerateSharedKey()
	if err != nil {
		t.Fatal(err)
	}

	concurrency := 100
	var wg sync.WaitGroup
	errChan := make(chan error, concurrency)

	start := time.Now()

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Interleave different hosts to force distinct cert generation
			host := fmt.Sprintf("sub-%d.example.com", id)

			leaf, err := GenerateLeafCert(ca, ca.Leaf, serverKey, host)
			if err != nil {
				errChan <- fmt.Errorf("routine %d failed: %v", id, err)
				return
			}

			// Validate the cert structure briefly
			if len(leaf.Certificate) == 0 {
				errChan <- fmt.Errorf("routine %d generated empty cert", id)
				return
			}

			// Verify it parses back correctly (catch ASN.1 marshaling races)
			_, err = x509.ParseCertificate(leaf.Certificate[0])
			if err != nil {
				errChan <- fmt.Errorf("routine %d generated corrupt ASN.1: %v", id, err)
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Report Results
	for err := range errChan {
		t.Error(err)
	}

	duration := time.Since(start)
	t.Logf("Generated %d certs in %v (%v/cert)", concurrency, duration, duration/time.Duration(concurrency))
}

// TestCertGeneration_ChainValidity ensures the generated leaf strictly adheres to
// the trust chain. A cert that parses but fails verification is useless.
func TestCertGeneration_ChainValidity(t *testing.T) {
	tmpDir := t.TempDir()
	ca, _ := LoadOrCreateCA(filepath.Join(tmpDir, "ca.crt"), filepath.Join(tmpDir, "ca.key"))
	serverKey, _ := GenerateSharedKey()

	leafTLS, err := GenerateLeafCert(ca, ca.Leaf, serverKey, "secure.internal")
	if err != nil {
		t.Fatal(err)
	}

	leafCert, _ := x509.ParseCertificate(leafTLS.Certificate[0])

	// Create a CertPool containing only our custom CA
	roots := x509.NewCertPool()
	roots.AddCert(ca.Leaf)

	opts := x509.VerifyOptions{
		DNSName: "secure.internal",
		Roots:   roots,
	}

	if _, err := leafCert.Verify(opts); err != nil {
		t.Errorf("Certificate chain verification failed: %v", err)
	}
}
