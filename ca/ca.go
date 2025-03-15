package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

// GenerateRootCA creates a root CA certificate and private key, saving them to files.
func GenerateRootCA() error {
	// Generate a 2048-bit RSA private key for the CA
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Define the CA certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1), // Unique identifier
		Subject: pkix.Name{
			Organization: []string{"Aegis CA"},
			CommonName:   "Aegis Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),                 // Valid for 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign, // For signing certificates
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create the self-signed CA certificate
	// The returned slice is the certificate in DER encoding
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// Save the certificate in PEM format
	certOut, err := os.Create("certs/ca.crt")
	if err != nil {
		return err
	}
	defer certOut.Close()
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return err
	}

	// Save the private key in PEM format
	keyOut, err := os.Create("certs/ca.key")
	if err != nil {
		return err
	}
	defer keyOut.Close()
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err != nil {
		return err
	}

	return nil
}

// LoadRootCA loads the CA certificate and key from files for use in the proxy.
func LoadRootCA() (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair("certs/ca.crt", "certs/ca.key")
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
