package proxy

import (
	"time"
	"math/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/rsa"
	"log"
	"net/http"
	"net/http/httputil"
	"aegis/ca"
)

type AegisProxy struct {
	proxy	*httputil.ReverseProxy
	caCert	tls.Certificate
	caCertPool *x509.CertPool
}

// NewProxy initializes the Aegis proxy with CA credentials.
func NewProxy() (*AegisProxy, error) {
	// Load the root CA
	caCert, err := ca.LoadRootCA()
	if err != nil {
		return nil, err
	}

	// Create a certificate pool with the CA certificate
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert.Leaf)

	// Configure the reverse proxy
	director := func(req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool, // Trust our CA for outgoing connections
		},
	}
	reverseProxy := &httputil.ReverseProxy{
		Director: director,
		Transport: transport,
	}

	return &AegisProxy{
		proxy:	reverseProxy,
		caCert:	*caCert,
		caCertPool: caCertPool,
	}, nil
}

// Start runs the proxy server on the specified address.
func (a *AegisProxy) Start(addr string) error {
	tlsConfig := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return generateCert(info.ServerName, a.caCert)
		},
	}

	server := &http.Server{
		Addr:	addr,
		Handler: a.proxy,
		TLSConfig: tlsConfig,
	}

	log.Printf("Starting Aegis proxy on %s", addr)
	return server.ListenAndServeTLS("","") // Certs handled dynamically
}

// generateCert creates a certificate for the requested domain, signed by the CA.
func generateCert(domain string, caCert tls.Certificate) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore: time.Now(),
		NotAfter: time.Now().AddDate(1, 0, 0), // Valid for 1 year
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames: []string{domain},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert.Leaf, &priv.PublicKey, caCert.PrivateKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey: priv,
	}
	return cert, nil
}
