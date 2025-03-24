// Package ca implements certificate authority functions.
// It generates, loads and manages the root CA certificate and key
// that will sign the generated certificates.
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
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

// Configuration constants for the CA certificate
const (
	DefaultCAPath         = "certs/ca.crt"
	DefaultCAKeyPath      = "certs/ca.key"
	DefaultCAKeyBits      = 4096
	DefaultCAValidity     = 10 * 365 * 24 * time.Hour
	DefaultCAOrganization = "Armor Security"
	DefaultCACommonName   = "Armor Proxy Root CA"
)

// CAConfig holds the configuration options for generating a Certificate Authority
type CAConfig struct {
	// CertPath is the file path to store the CA certificate
	CertPath string

	// KeyPath is the file path to store the CA private key
	KeyPath string

	// KeyBits is the RSA key size in bits
	KeyBits int

	// Validity defines how long the CA certificate will be valid
	Validity time.Duration

	// Organization is the organization name in the certificate
	Organization string

	// CommonName is the common name in the CA certificate
	CommonName string
}

// DefaultCAConfig returns a default configuration for CA certificate generation
func DefaultCAConfig() CAConfig {
	return CAConfig{
		CertPath:     DefaultCAPath,
		KeyPath:      DefaultCAKeyPath,
		KeyBits:      DefaultCAKeyBits,
		Validity:     DefaultCAValidity,
		Organization: DefaultCAOrganization,
		CommonName:   DefaultCACommonName,
	}
}

// GenerateRootCA creates a root CA certificate and private key
// It uses the default configuration parameters.
//
// Returns an error if the certificate generation or saving fails.
func GenerateRootCA() error {
	return GenerateRootCAWithConfig(DefaultCAConfig())
}

// GenerateRootCAWithConfig creates a root CA certificate and private key
// with custom configuration.
//
// Returns an error if the certificate generation or saving fails.
func GenerateRootCAWithConfig(config CAConfig) error {
	certDir := filepath.Dir(config.CertPath)
	keyDir := filepath.Dir(config.KeyPath)

	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, config.KeyBits)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			Organization: []string{config.Organization},
			CommonName:   config.CommonName,
		},
		NotBefore:             now.Add(-1 * time.Hour), // backdate it to avoid clock skew issues
		NotAfter:              now.Add(config.Validity),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// create self-signed CA certificate (signed by its own key)
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template, // certificate template
		&template, // parent is same as template, because self-signed
		&priv.PublicKey,
		priv, // certificate will be signed by this private key
	)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	certOut, err := os.Create(config.CertPath)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to encode certificate to PEM: %w", err)
	}

	keyOut, err := os.OpenFile(config.KeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	err = pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	if err != nil {
		return fmt.Errorf("failed to encode private key to PEM: %w", err)
	}

	return nil
}

// LoadRootCA loads the CA certificate and key from the default paths.
func LoadRootCA() (*tls.Certificate, error) {
	return LoadRootCAFromPath(DefaultCAPath, DefaultCAKeyPath)
}

// LoadRootCAFromPath loads a CA certificate and key from specified file paths.
func LoadRootCAFromPath(certPath, keyPath string) (*tls.Certificate, error) {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("certificate file not found: %s", certPath)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("key file not found: %s", keyPath)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate and key: %w", err)
	}

	// more like a defensive check to make it future-proof
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate data found in %s", certPath)
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// parsing (x509.ParseCertificate) is expensive, to avoid it later,
	// the Leaf field in tls.Certificate is used to store the parsed version.
	// `Leaf` is a pointer to the parsed x509.Certificate; it is not set automatically
	// by tls.LoadX509KeyPair
	cert.Leaf = parsedCert

	if !parsedCert.IsCA {
		return nil, fmt.Errorf("loaded certificate is not a CA certificate")
	}

	return &cert, nil
}

// InstallCACertificate helps install the CA certificate into the system trust store.
// This function returns instructions for the user to follow based on their OS.
// Possible future improvement: Install the certificate automatically.
func InstallCACertificate(certPath string) string {
	instructions := fmt.Sprintf(`
	To trust the Armor Proxy CA certificate, follow these instructions for your OS:

	CA Certificate Location: %s

	Windows:
	I. Double-click the CA certificate file
	II. Click "Install Certificate"
	III. Select "Local Machine" and click "Next"
	IV. Select "Place all certificates in the following store"
	V. Click "Browse" and select "Trusted Root Certification Authorities"
	VI. Click "Next" and then "Finish"

	macOS:
	I. Double-click the CA certificate file
	II. It will open in Keychain Access
	III. Enter your password to unlock the keychain
	IV. The certificate will be added but not trusted yet
	V. Find the certificate in the list, double-click it
	VI. Expand the "Trust" section
	VII. Change "When using this certificate" to "Always Trust"
	VIII. Close the window and enter your password again

	Linux (Debian/Ubuntu):
	I. Copy the certificate: sudo cp %s /usr/local/share/ca-certificates/armor-proxy-ca.crt
	II. Update the CA store: sudo update-ca-certificates

	Linux (Fedora/RHEL):
	I. Copy the certificate: sudo cp %s /etc/pki/ca-trust/source/ancors/armor-proxy-ca.crt
	II. Update the CA store: sudo update-ca-trust

	Firefox (All platforms):
	Firefox uses its own certificate store:
	I. Open Firefox and go to Settings/Preferences
	II. Search for "certificates" and click "View Certificates"
	III. Go to the "Authorities" tab
	IV. Click "Import" and select the CA certificate file
	V. Check "Trust this CA to identify websites" and click "OK"
	`, certPath, certPath, certPath)

	return instructions
}

// GenerateClientCertificate creates a client certificate signed by the CA.
func GenerateClientCertificate(commonName string, caCert tls.Certificate, outCertPath, outKeyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate client certificate private key: %w", err)
	}

	// TODO: Check if I can avoid parsing by getting the Leaf field...
	ca, err := x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Armor Proxy Client"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		ca, // Parent
		&priv.PublicKey,
		caCert.PrivateKey,
	)
	if err != nil {
		return fmt.Errorf("failed to create client certificate: %w", err)
	}

	certOut, err := os.Create(outCertPath)
	if err != nil {
		return fmt.Errorf("failed to create client certificate: %w", err)
	}
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return fmt.Errorf("failed to encode client certificate to PEM: %w", err)
	}

	keyOut, err := os.OpenFile(outKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create client key file: %w", err)
	}
	defer keyOut.Close()

	err = pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	if err != nil {
		return fmt.Errorf("failed to encode client private key to PEM: %w", err)
	}

	return nil
}

// GenerateServerCertificate creates an in-memory server certificate signed by the CA.
func GenerateServerCertificate(hostname string, caCert tls.Certificate) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server certificate private key: %w", err)
	}

	var ca *x509.Certificate
	if caCert.Leaf != nil {
		ca = caCert.Leaf
	} else {
		ca, err = x509.ParseCertificate(caCert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
		}
	}

	ipAddresses := []net.IP{}
	dnsNames := []string{hostname}

	if ip := net.ParseIP(hostname); ip != nil {
		ipAddresses = append(ipAddresses, ip)
		dnsNames = []string{}
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"Armor Proxy Server"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(0, 1, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		ca, // Parent
		&priv.PublicKey,
		caCert.PrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	cert.Leaf, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	return cert, nil
}
