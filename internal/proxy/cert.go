// FILENAME: internal/proxy/cert.go
package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// CertManager handles the lifecycle of the CA and leaf certificates.
type CertManager struct {
	ca        tls.Certificate
	caParsed  *x509.Certificate
	serverKey *ecdsa.PrivateKey
	certCache map[string]*tls.Certificate
	mu        sync.RWMutex
	logger    *zap.Logger
}

func NewCertManager(certDirOverride string, logger *zap.Logger) (*CertManager, error) {
	certDir := certDirOverride
	var err error
	if certDir == "" {
		certDir, err = resolveSafeCertDir(logger)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve safe cert directory: %w", err)
		}
	}

	// Ensure the directory exists with strict 0700 permissions
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cert dir: %w", err)
	}

	certPath := filepath.Join(certDir, "ca.pem")
	keyPath := filepath.Join(certDir, "ca.key")

	logger.Info("Loading CA identity", zap.String("path", certDir))

	ca, err := LoadOrCreateCA(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	caParsed, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Generate a shared key for leaf certificates to avoid expensive key gen per request
	serverKey, err := GenerateSharedKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared key: %w", err)
	}

	return &CertManager{
		ca:        ca,
		caParsed:  caParsed,
		serverKey: serverKey,
		certCache: make(map[string]*tls.Certificate),
		logger:    logger,
	}, nil
}

// GetCA returns the Root CA certificate used by this manager.
func (cm *CertManager) GetCA() tls.Certificate {
	return cm.ca
}

// GetOrCreate retrieves or generates a certificate for a specific host.
func (cm *CertManager) GetOrCreate(host string) (*tls.Certificate, error) {
	cm.mu.RLock()
	leaf, hit := cm.certCache[host]
	cm.mu.RUnlock()

	if hit {
		return leaf, nil
	}

	// Double-checked locking
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if leaf, hit := cm.certCache[host]; hit {
		return leaf, nil
	}

	leaf, err := GenerateLeafCert(cm.ca, cm.caParsed, cm.serverKey, host)
	if err != nil {
		return nil, err
	}

	// Simple cache eviction
	if len(cm.certCache) > 1000 {
		cm.certCache = make(map[string]*tls.Certificate)
	}
	cm.certCache[host] = leaf
	return leaf, nil
}

// resolveSafeCertDir resolves the directory with strict validation.
func resolveSafeCertDir(logger *zap.Logger) (string, error) {
	var homeDir string
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && os.Geteuid() == 0 {
		u, err := user.Lookup(sudoUser)
		if err == nil {
			homeDir = u.HomeDir
			logger.Debug("Using SUDO_USER home for cert storage", zap.String("user", sudoUser))
		}
	}

	if homeDir == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		homeDir = h
	}

	targetDir := filepath.Join(homeDir, ".scalpel-racer", "certs")
	return filepath.Clean(targetDir), nil
}

// LoadOrCreateCA loads existing certs or generates new ones using ECDSA P-256.
func LoadOrCreateCA(certFile, keyFile string) (tls.Certificate, error) {
	// 1. Try to load existing pair
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return tls.Certificate{}, fmt.Errorf("failed to load CA: %w", err)
			}
			if len(cert.Certificate) > 0 {
				cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
			}
			return cert, nil
		}
	}

	// 2. Generate new CA with ECDSA P-256
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate CA key: %w", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to marshal public key: %w", err)
	}
	ski := sha1.Sum(pubKeyBytes)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Scalpel Racer CA",
			Organization: []string{"Scalpel Research"},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          ski[:],
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return tls.Certificate{}, err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	return cert, nil
}

// GenerateSharedKey creates a shared ECDSA key.
func GenerateSharedKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenerateLeafCert signs a certificate using the shared ECDSA key.
func GenerateLeafCert(ca tls.Certificate, caCert *x509.Certificate, serverKey *ecdsa.PrivateKey, host string) (*tls.Certificate, error) {
	if serverKey == nil {
		return nil, fmt.Errorf("shared server key is nil")
	}

	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// FIX: Handle IPv6 literals (e.g. "[::1]") by stripping brackets
	host = strings.Trim(host, "[]")

	var ipAddrs []net.IP
	var dnsNames []string
	if ip := net.ParseIP(host); ip != nil {
		ipAddrs = append(ipAddrs, ip)
	} else {
		dnsNames = append(dnsNames, host)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber:   serialNumber,
		Subject:        pkix.Name{CommonName: host},
		NotBefore:      time.Now().Add(-5 * time.Minute),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:       dnsNames,
		IPAddresses:    ipAddrs,
		AuthorityKeyId: caCert.SubjectKeyId,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	leaf, _ := x509.ParseCertificate(der)

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  serverKey,
		Leaf:        leaf,
	}
	return &cert, nil
}
