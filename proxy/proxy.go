package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/akos011221/armor/ca"
	"github.com/akos011221/armor/filter"
)

// ArmorProxy represents MITM (man-in-the-middle) proxy.
type ArmorProxy struct {
	// caCert holds the Certificate Authority certificate used to sign the generated certificates
	caCert tls.Certificate

	// caCertPool is a pool of trusted certificates, contains the CA certificate
	// This is used when connecting to upstream servers
	caCertPool *x509.CertPool

	// certCache stores the generated certificates for different hosts
	// We use cache to avoid regenerating for frequently visited sites
	certCache map[string]*tls.Certificate

	// mu protects the certCache from concurrent read/write operations
	mu sync.RWMutex

	// logger provides organized logging
	logger *log.Logger

	// config contains the proxy's configuration options
	config ProxyConfig
}

// ProxyConfig holds the configurations options for the proxy.
type ProxyConfig struct {
	// CA certificate configuration
	CaCfg	ca.CAConfig

	// Listening address and port
	ListenAddr string

	// If true, detailed logging is enabled
	Verbose bool

	// Maximum number of certificates to keep in memory
	CertCacheSize int

	// Maximum time to wait reading from connections
	ReadTimeout time.Duration

	// Maximum time to wait when writing to connections
	WriteTimeout time.Duration

	// If true, proxy will not validate server certificates
	AllowInsecure bool

	// Where to send the logs (e.g., os.Stdout, a file, etc.)
	LogDestination io.Writer
}

// DefaultConfig returns a default configuration for the proxy.
func DefaultConfig() ProxyConfig {
	return ProxyConfig{
		CaCfg:		ca.DefaultCAConfig(),
		ListenAddr:     ":4090",
		Verbose:        true,
		CertCacheSize:  1000,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		AllowInsecure:  false,
		LogDestination: os.Stdout,
	}
}

// NewProxy initializes the Armor proxy with the given configuration.
func NewProxy(p ProxyConfig) (*ArmorProxy, error) {
	var caCert *tls.Certificate
	var err error

	// Check if CA certificate files exist
	_, certErr := os.Stat(p.CaCfg.CertPath)
	_, keyErr := os.Stat(p.CaCfg.KeyPath)

	// If they don't exist, generate new CA certificate
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		if err = ca.GenerateRootCAWithConfig(p.CaCfg); err != nil {
			return nil, fmt.Errorf("failed to generate CA certificate: %w", err)
		}
	}

	// Load the CA certificate
	caCert, err = ca.LoadRootCAFromPath(p.CaCfg.CertPath, p.CaCfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// Create CA certificate pool for verifying server certificates
	caCertPool := x509.NewCertPool()
	if caCert.Leaf == nil {
		// If Leaf is not populated, parse the certificate
		leaf, err := x509.ParseCertificate(caCert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
		}
		caCert.Leaf = leaf
	}
	caCertPool.AddCert(caCert.Leaf)

	logger := log.New(p.LogDestination, "ArmorProxy: ", log.LstdFlags)

	return &ArmorProxy{
		caCert: *caCert,
		caCertPool: caCertPool,
		certCache: make(map[string]*tls.Certificate),
		mu: sync.RWMutex{},
		logger: logger,
		config: p,
	}, nil
}

// Start runs an HTTP server for the proxy.
func (a *ArmorProxy) Start(addr string) error {
	server := &http.Server{
		Addr:    a.config.ListenAddr,
		Handler: a, // ArmorProxy implements http.Handler
		ReadTimeout: a.config.ReadTimeout,
		WriteTimeout: a.config.WriteTimeout,
	}

	a.logger.Printf("Starting Armor proxy on %s", addr)
	return server.ListenAndServe()
}

// ServeHTTP implements the http.Handler interface.
// It is called for each incoming HTTP request.
func (a *ArmorProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Log the incoming request if verbose logging is enabled
	if a.config.Verbose {
		a.logger.Printf("Received request: %s %s", r.Method, r.URL)
	}

	// Apply filters
	if filter.ApplyFilter(w, r) {
		a.logger.Printf("Blocked request to %s", r.Host)
		return
	}

	// Handle CONNECT requests (for HTTPS connections)
	// HTTP CONNECT method is used to establish a tunnel for HTTPS traffic
	if r.Method == http.MethodConnect {
		a.handleConnect(w, r)
		return
	}

	// Forward non-CONNECT requests
	a.forwardRequest(w, r)
}

// handleConnect handles HTTPS tunneling by establishing a MITM connection.
/* The process is the following:
	I. Hijacks the connection from the HTTP server
	II. Establishes a TLS connection with the client using a generated certificate
	III. Establishes a TLS connection with the target server
	IV. Copies data bidirectionally between the client and target
*/
func (a *ArmorProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	/*
	 Hijack the connection to establish a tunnel
	 When it receive a CONNECT, we need to handle it manually
	 Reason is that it is not a standard HTTP request/respose cycle
	*/
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		// Not all http.ResponseWriter implementations support hijacking
		a.logger.Printf("Error: ResponsrWriter doesn't support hijacking.")
		http.Error(w, "Hijacking is not supported", http.StatusInternalServerError)
		return
	}
	
	// Get the underlying connection
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		a.logger.Printf("Error hijacking connection: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Notify client that the tunnel is built
	// This is the standard response for a successful CONNECT request
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connectoin Established\r\n\r\n")); err != nil {
		a.logger.Printf("Error writing to client connection: %v", err)
		clientConn.Close()
		return
	}

	// Extract the hostname from the request
	// We need it to generate a certificate for the host
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	// Generate or retrieve a certificate for the requested host
	cert, err := a.getCertificate(host)
	if err != nil {
		a.logger.Printf("Error getting certificate for %s: %v", host, err)
		clientConn.Close()
		return
	}

	// Establish a TLS connection with the client with the generated certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	defer tlsClientConn.Close()

	// TLS handshake with client
	if err := tlsClientConn.Handshake(); err != nil {
		a.logger.Printf("Error in TLS handshake with client: %v", err)
		return
	}

	// Establish a TLS connection to the target server
	targetConn, err := tls.Dial("tcp", r.Host, &tls.Config{
		RootCAs: a.caCertPool,
		InsecureSkipVerify: a.config.AllowInsecure,
	})
	if err != nil {
		a.logger.Printf("Error connecting to target server: %s: %v", r.Host, err)
		return
	}
	defer targetConn.Close()

	// Bidirectional copying of data between client and target server
	var wg sync.WaitGroup
	wg.Add(2)

	// Copy data from client to target server
	go func() {
		defer wg.Done()
		if _, err := io.Copy(targetConn, tlsClientConn); err != nil && !isClosedConnError(err) {
			a.logger.Printf("Error copying data from client to target: %v", err)
		}
		// Close the target connection to signal EOF
		targetConn.Close()
	}()

	// Copy data from target server to client
	go func() {
		defer wg.Done()
		if _, err := io.Copy(tlsClientConn, targetConn); err != nil && !isClosedConnError(err) {
			a.logger.Printf("Error copying data from target to client: %v", err)
		}
		// Close the client connection to signal EOF
		tlsClientConn.Close()
	}()

	// Wait for both copy operations to complete
	// We make sure not to exit the function until the connection is closed
	wg.Wait()

	// Log connection closure if verbose logging is enabled
	if a.config.Verbose {
		a.logger.Printf("Closed connection to %s", r.Host)
	}
}

// forwardRequest forwards (non-CONNECT) HTTP requests to the destination server.
/* The process is the following:
	I. Creates a new HTTP transport with the custom options
	II. Clones the request, prepares it for forwarding
	III. Sends the request to the target server
	IV. Forwards the response back to the client
*/
func (a *ArmorProxy) forwardRequest(w http.ResponseWriter, r *http.Request) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:            a.caCertPool,
			InsecureSkipVerify: a.config.AllowInsecure,
		},
		ResponseHeaderTimeout: a.config.ReadTimeout,
	}

	// Clone the request, so we don't modify the original
	reqClone := r.Clone(r.Context())

	// There are hop-by-hop headers, that must not be retransmitted by proxies
	// They are scoped to a single hop, not for the entire request chain
	removeHopByHop(reqClone)

	// Ensure the request URL is absolute
	if reqClone.URL.Scheme == "" {
		reqClone.URL.Scheme = "http"
	}
	if reqClone.URL.Host == "" {
		reqClone.URL.Host = reqClone.Host
	}

	// Log the forwarded request if verbose logging is enabled
	if a.config.Verbose {
		a.logger.Printf("Forwarding request to %s", reqClone.URL)
	}

	// Send the request to the target server
	resp, err := transport.RoundTrip(reqClone)
	if err != nil {
		a.logger.Printf("Error forwarding request :%v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	// Remove hop-by-hop headers from the response
	removeHopByHop(resp)

	// Copy response headers to the client
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Write status code and body
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		a.logger.Printf("Error copying response body: %v", err)
	}
}

// getCertificate retrieves or generates a certificate for the given host.
func (a *ArmorProxy) getCertificate(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Remove port if present
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	// Try the cache first
	if cert, exists := a.certCache[hostname]; exists {
		if a.config.Verbose {
			a.logger.Printf("Using cached certificate for %s", hostname)
		}
		return cert, nil
	}

	// Generate new certificate for this host
	if a.config.Verbose {
		a.logger.Printf("Generating new certificate for %s", hostname)
	}

	cert, err := ca.GenerateServerCertificate(hostname, a.caCert)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate for %s: %w", hostname, err)
	}

	// Add to cache if we haven't exceeded the cache size limit
	if len(a.certCache) < a.config.CertCacheSize {
		a.certCache[hostname] = cert
	}

	return cert, nil
}

// TODO: Remove the hop-by-hop headers
// TODO: Handle errors when peers try to write to a closed connection
