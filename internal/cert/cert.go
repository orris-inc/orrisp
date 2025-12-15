// Package cert provides utilities for TLS certificate generation.
package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// SelfSignedCert holds paths to generated certificate and key files.
type SelfSignedCert struct {
	CertPath string
	KeyPath  string
}

// GenerateSelfSigned generates a self-signed certificate and saves it to the specified directory.
// If sni is empty, it defaults to "localhost".
func GenerateSelfSigned(dir string, sni string) (*SelfSignedCert, error) {
	if sni == "" {
		sni = "localhost"
	}

	// Generate Ed25519 private key (faster and more secure than ECDSA P-256)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Orris Self-Signed"},
			CommonName:   sni,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{sni},
	}

	// Add IP address if sni looks like an IP
	if ip := net.ParseIP(sni); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create certificate directory: %w", err)
	}

	// Write certificate file
	certPath := filepath.Join(dir, "server.crt")
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return nil, fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key file
	keyPath := filepath.Join(dir, "server.key")
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	// Marshal Ed25519 private key to PKCS#8 format
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}

	return &SelfSignedCert{
		CertPath: certPath,
		KeyPath:  keyPath,
	}, nil
}

// isCertValid checks if certificate file is valid and not expired
func isCertValid(certPath string) bool {
	// Read certificate file
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}

	// Decode PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	// Check if certificate is expired or will expire in next 30 days
	now := time.Now()
	expiryBuffer := 30 * 24 * time.Hour // 30 days
	return now.After(cert.NotBefore) && now.Add(expiryBuffer).Before(cert.NotAfter)
}

// EnsureCert ensures certificate files exist at the given paths.
// If they don't exist or are expired, generates self-signed certificates.
func EnsureCert(certPath, keyPath, sni string) (string, string, error) {
	// Check if both files exist and certificate is valid
	if certPath != "" && keyPath != "" {
		if _, err := os.Stat(certPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil {
				// Check certificate validity
				if isCertValid(certPath) {
					return certPath, keyPath, nil
				}
			}
		}
	}

	// Generate self-signed certificate
	dir := filepath.Dir(certPath)
	if dir == "" || dir == "." {
		dir = "/var/lib/orrisp/certs"
	}

	cert, err := GenerateSelfSigned(dir, sni)
	if err != nil {
		return "", "", err
	}

	return cert.CertPath, cert.KeyPath, nil
}
