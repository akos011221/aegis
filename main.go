package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/akos011221/armor/ca"
	"github.com/akos011221/armor/proxy"
)

func main() {
	// Testing with the default configuration
	//config := proxy.DefaultConfig()

	// Create a new instance of the proxy
	p, err := proxy.NewProxy(&proxy.ProxyConfig{
		CaCfg:          ca.DefaultCAConfig(),
		ListenAddrHTTP: ":4090",
		ListenAddrTLS:  ":4091",
		Verbose:        true,
		CertCacheSize:  1000,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		AllowInsecure:  false,
		EnabledPlugins: []string{"blocklist"},
		PluginsConfig: map[string]any{
			"blocklist": map[string]bool{
				"facebook.com": true,
			},
			"block_methods": map[string]bool{
				http.MethodTrace: true,
				http.MethodPut:   true,
			},
		},
		LogDestination: os.Stdout,
	})
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// Start HTTP proxy
	if err = p.StartHTTP(":4090"); err != nil {
		log.Fatalf("HTTP proxy failed: %v", err)
	}

	// Start HTTPS proxy; TODO: create TLS certificate for the proxy
	// p.StartHTTPS(":4091")

}
