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
	"time"
)

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

	// 2. Generate new CA with ECDSA P-256 (Much faster than RSA)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Marshal public key for SKI generation
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
	// Marshal EC Private Key
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
	// ... [Host splitting logic remains the same] ...
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// ... [IP parsing logic remains the same] ...
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

	// Use ECDSA keys for creation
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
