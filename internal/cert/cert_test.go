package cert

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"
)

func TestGenerateSelfSigned_ECDSA(t *testing.T) {
	// Create temp directory
	dir := t.TempDir()

	// Generate certificate
	cert, err := GenerateSelfSigned(dir, "test.example.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Check files exist
	if _, err := os.Stat(cert.CertPath); err != nil {
		t.Errorf("Certificate file does not exist: %v", err)
	}
	if _, err := os.Stat(cert.KeyPath); err != nil {
		t.Errorf("Key file does not exist: %v", err)
	}

	// Read and parse certificate
	certPEM, err := os.ReadFile(cert.CertPath)
	if err != nil {
		t.Fatalf("Failed to read certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("Failed to decode certificate PEM")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify it's ECDSA
	if certificate.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("Expected ECDSA public key algorithm, got %v", certificate.PublicKeyAlgorithm)
	}

	// Verify common name
	if certificate.Subject.CommonName != "test.example.com" {
		t.Errorf("Expected CN=test.example.com, got %s", certificate.Subject.CommonName)
	}

	// Verify validity period
	now := time.Now()
	if now.Before(certificate.NotBefore) {
		t.Error("Certificate is not yet valid")
	}
	if now.After(certificate.NotAfter) {
		t.Error("Certificate is already expired")
	}

	// Read and verify key
	keyPEM, err := os.ReadFile(cert.KeyPath)
	if err != nil {
		t.Fatalf("Failed to read key: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("Failed to decode key PEM")
	}

	// PKCS#8 format uses "PRIVATE KEY" type
	if keyBlock.Type != "PRIVATE KEY" {
		t.Errorf("Expected PRIVATE KEY PEM type, got %s", keyBlock.Type)
	}
}

func TestIsCertValid(t *testing.T) {
	dir := t.TempDir()

	// Generate certificate
	cert, err := GenerateSelfSigned(dir, "test.example.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Should be valid
	if !isCertValid(cert.CertPath) {
		t.Error("Certificate should be valid")
	}

	// Non-existent certificate should be invalid
	if isCertValid("/nonexistent/path") {
		t.Error("Non-existent certificate should be invalid")
	}
}

func TestEnsureCert(t *testing.T) {
	dir := t.TempDir()
	certPath := dir + "/server.crt"
	keyPath := dir + "/server.key"

	// First call should generate certificate
	cert1, key1, err := EnsureCert(certPath, keyPath, "test.example.com")
	if err != nil {
		t.Fatalf("Failed to ensure certificate: %v", err)
	}

	// Second call should reuse existing certificate
	cert2, key2, err := EnsureCert(certPath, keyPath, "test.example.com")
	if err != nil {
		t.Fatalf("Failed to ensure certificate on second call: %v", err)
	}

	if cert1 != cert2 || key1 != key2 {
		t.Error("Certificate should be reused on second call")
	}
}
