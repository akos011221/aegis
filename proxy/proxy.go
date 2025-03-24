package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/akos011221/armor/ca"
	"github.com/akos011221/armor/helpers"
	"github.com/akos011221/armor/plugin"
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

	// pluginManager manages the enabled plugins
	pluginManager *plugin.ArmorPluginManager

	// config contains the proxy's configuration options
	config *ProxyConfig
}

// ProxyConfig holds the configurations options for the proxy.
type ProxyConfig struct {
	// CA certificate configuration
	CaCfg ca.CAConfig

	// Listening address and port for HTTP
	ListenAddrHTTP string

	// Listening address and port for TLS
	ListenAddrTLS string

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

	// Name of the plugins that should be enabled
	EnabledPlugins []string

	// Map that contains the plugin configurations
	PluginsConfig map[string]any

	// Where to send the logs (e.g., os.Stdout, a file, etc.)
	LogDestination io.Writer
}

// DefaultConfig returns a default configuration for the proxy.
func DefaultConfig() *ProxyConfig {
	return &ProxyConfig{
		CaCfg:          ca.DefaultCAConfig(),
		ListenAddrHTTP: ":4090",
		ListenAddrTLS:  ":4091",
		Verbose:        true,
		CertCacheSize:  1000,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		AllowInsecure:  false,
		EnabledPlugins: make([]string, 0),
		PluginsConfig:  make(map[string]any, 0),
		LogDestination: os.Stdout,
	}
}

// NewProxy initializes the Armor proxy with the given configuration.
func NewProxy(p *ProxyConfig) (*ArmorProxy, error) {
	var caCert *tls.Certificate
	var err error

	// check if the cert and key files exist
	_, certErr := os.Stat(p.CaCfg.CertPath)
	_, keyErr := os.Stat(p.CaCfg.KeyPath)

	// if any of them is missing, generate a new CA cert
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		if err = ca.GenerateRootCAWithConfig(p.CaCfg); err != nil {
			return nil, fmt.Errorf("failed to generate CA certificate: %w", err)
		}
	}

	caCert, err = ca.LoadRootCAFromPath(p.CaCfg.CertPath, p.CaCfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// get the system's cert pool
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		// or create a new one if we can't get it
		caCertPool = x509.NewCertPool()
	}

	// leaf holds the parsed certificate; check if it's populated
	if caCert.Leaf == nil {
		leaf, err := x509.ParseCertificate(caCert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
		}
		caCert.Leaf = leaf
	}
	// add the CA cert to the pool
	caCertPool.AddCert(caCert.Leaf)

	logger := log.New(p.LogDestination, "armor: ", log.LstdFlags)

	manager, err := initPlugins(p.EnabledPlugins, p.PluginsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin manager: %w", err)
	}

	return &ArmorProxy{
		caCert:        *caCert,
		caCertPool:    caCertPool,
		certCache:     make(map[string]*tls.Certificate),
		mu:            sync.RWMutex{},
		logger:        logger,
		pluginManager: manager,
		config:        p,
	}, nil
}

// StartHTTP runs an HTTP server for the proxy.
func (a *ArmorProxy) StartHTTP(addr string) error {
	server := &http.Server{
		Addr:         a.config.ListenAddrHTTP,
		Handler:      a, // ArmorProxy implements http.Handler
		ReadTimeout:  a.config.ReadTimeout,
		WriteTimeout: a.config.WriteTimeout,
	}

	a.logger.Printf("Starting Armor proxy on %s", addr)
	return server.ListenAndServe()
}

// StartTLS runs a TLS server for the proxy.
func (a *ArmorProxy) StartTLS(addr string, certFile, keyFile string) error {
	server := &http.Server{
		Addr:         a.config.ListenAddrTLS,
		Handler:      a, // ArmorProxy implements http.Handler
		ReadTimeout:  a.config.ReadTimeout,
		WriteTimeout: a.config.WriteTimeout,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{a.caCert},
		},
	}

	a.logger.Printf("Starting Armor HTTPS proxy on %s", addr)
	return server.ListenAndServeTLS(certFile, keyFile)
}

// ServeHTTP implements the http.Handler interface.
// It is called for each incoming HTTP request.
func (a *ArmorProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.config.Verbose {
		a.logger.Printf("Received request: %s %s", r.Method, r.URL)
	}

	// apply initial plugin processing
	pluginName, status, err := a.pluginManager.ProcessInitReq(r)
	if err != nil {
		a.logger.Printf("Error sent by %s: %v", pluginName, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if status >= 400 && status < 500 {
		a.logger.Printf("Plugin %s terminated the request", pluginName)
		http.Error(w, fmt.Sprintf("Request was terminated by %s", pluginName), status)
		return
	}

	// Handle CONNECT requests
	// HTTP CONNECT method is used to establish a tunnel
	if r.Method == http.MethodConnect {
		a.handleConnect(w, r)
		return
	}

	// Forward non-CONNECT requests
	a.forwardRequest(w, r)
}

// handleConnect handles HTTP tunneling by establishing a MITM connection.
/* The process is the following:
I. Hijacks the connection from the HTTP server
II. Establishes a TLS connection with the client using a generated certificate
III. Establishes a TLS connection with the target server
IV. Copies data bidirectionally between the client and target
*/
func (a *ArmorProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// need to hijack the connection to intercept after CONNECT completes
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		// not all http.ResponseWriter implementations support hijacking
		a.logger.Printf("Error: ResponseWriter doesn't support hijacking.")
		http.Error(w, "Hijacking is not supported", http.StatusInternalServerError)
		return
	}

	// method Hijack gets us the underlying net.Conn
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		a.logger.Printf("Error hijacking connection: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// send the standard response for a successful CONNECT request
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		a.logger.Printf("Error writing to client connection: %v", err)
		clientConn.Close()
		return
	}

	/*
		the following code establishes a TLS connection with the client,
		while the proxy tricks the client into thinking it's the target,
		by using a generated a TLS cert for the requested host.
	*/

	cert, err := a.getCertificate(r.Host)
	if err != nil {
		a.logger.Printf("Error getting certificate for %s: %v", r.Host, err)
		clientConn.Close()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	defer tlsClientConn.Close()

	if err := tlsClientConn.Handshake(); err != nil {
		a.logger.Printf("Error in TLS handshake with client: %v", err)
		return
	}

	targetConn, err := tls.Dial("tcp", r.Host, &tls.Config{
		RootCAs:            a.caCertPool,
		InsecureSkipVerify: a.config.AllowInsecure,
	})
	if err != nil {
		a.logger.Printf("Error connecting to target server: %s: %v", r.Host, err)
		return
	}
	defer targetConn.Close()

	// wg is used to wait for both sides of the connection to finish
	var wg sync.WaitGroup
	wg.Add(2)

	// client -> target copying
	go func() {
		defer wg.Done()

		var b bytes.Buffer
		tee := io.TeeReader(tlsClientConn, &b)

		// parse the request so it can be passed to the plugins
		r, err := http.ReadRequest(bufio.NewReader(tee))
		if err != nil {
			a.logger.Printf("Error reading request: %v", err)
			return
		}

		pluginName, status, err := a.pluginManager.ProcessMitmReq(r)
		fmt.Printf("ProcessMitmReq returned code is: %d\n", status)
		if err != nil {
			a.logger.Printf("Error sent by %s: %v", pluginName, err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			targetConn.Close()
		}
		if status >= 400 && status < 500 {
			a.logger.Printf("Plugin %s terminated the request", pluginName)
			http.Error(w, fmt.Sprintf("Request was terminated by %s", pluginName), status)
			targetConn.Close()
		}

		// copy the buffered data to the target
		if _, err := io.Copy(targetConn, &b); err != nil {
			a.logger.Printf("Error copying buffered data to target: %v", err)
		}

		// and then also copy the rest of the data
		if _, err := io.Copy(targetConn, tlsClientConn); err != nil && !isClosedConnError(err) {
			a.logger.Printf("Error copying data from client to target: %v", err)
		}
		targetConn.Close()
	}()

	// target -> client copying
	go func() {
		defer wg.Done()
		if _, err := io.Copy(tlsClientConn, targetConn); err != nil && !isClosedConnError(err) {
			a.logger.Printf("Error copying data from target to client: %v", err)
		}
		tlsClientConn.Close()
	}()

	wg.Wait()

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

	// clone, so we don't modify the original request
	rr := r.Clone(r.Context())

	// hop-by-hop headers are scoped to a single hop, and should be removed
	removeHopByHop(rr)

	if rr.URL.Scheme == "" {
		rr.URL.Scheme = "http"
	}
	if rr.URL.Host == "" {
		rr.URL.Host = rr.Host
	}

	if a.config.Verbose {
		a.logger.Printf("Forwarding request to %s", rr.URL)
	}

	resp, err := transport.RoundTrip(rr)
	if err != nil {
		a.logger.Printf("Error forwarding request :%v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	// hop-by-hop headers should be removed from the response as well
	removeHopByHop(resp)

	// copy headers from the response to the client
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		a.logger.Printf("Error copying response body: %v", err)
	}
}

// getCertificate retrieves or generates a certificate for the given host.
func (a *ArmorProxy) getCertificate(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	hostWithoutPort := helpers.HostWithoutPort(host)

	// try the cache first
	if cert, exists := a.certCache[hostWithoutPort]; exists {
		if a.config.Verbose {
			a.logger.Printf("Using cached certificate for %s", host)
		}
		return cert, nil
	}

	if a.config.Verbose {
		a.logger.Printf("Generating new certificate for %s", hostWithoutPort)
	}

	cert, err := ca.GenerateServerCertificate(hostWithoutPort, a.caCert)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate for %s: %w", hostWithoutPort, err)
	}

	// only cache if there's space in the cache
	if len(a.certCache) < a.config.CertCacheSize {
		a.certCache[hostWithoutPort] = cert
	}

	return cert, nil
}

// removeHopByHop removes hop-by-hop headers as defined in RFC 2616
func removeHopByHop(message any) {
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	switch v := message.(type) {
	case *http.Request:
		for _, header := range hopByHopHeaders {
			v.Header.Del(header)
		}
	case *http.Response:
		for _, header := range hopByHopHeaders {
			v.Header.Del(header)
		}
	}
}

// isClosedConnError checks if the error is due to a closed connection
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || strings.Contains(err.Error(), "use of closed network connection")
}

// initPlugins initializes the plugin manager and factory with the configuration provided to the proxy instance.
func initPlugins(pluginNames []string, pluginsConfig map[string]any) (*plugin.ArmorPluginManager, error) {
	manager := plugin.NewArmorPluginManager()
	factory := plugin.NewArmorPluginFactory()

	var plugins []plugin.ArmorPlugin
	for _, pluginName := range pluginNames {
		p, err := factory.CreatePlugin(pluginName, pluginsConfig)
		if err != nil {
			return nil, fmt.Errorf("plugin factory failed to create %s", pluginName)
		}
		plugins = append(plugins, p)
	}

	for _, plugin := range plugins {
		manager.Register(plugin)
	}

	return manager, nil
}
