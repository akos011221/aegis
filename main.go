package main

import (
	"log"

	"github.com/akos011221/armor/proxy"
)

func main() {
	// Testing with the default configuration
	config := proxy.DefaultConfig()
	
	// Create a new instance of the proxy
	p, err := proxy.NewProxy(config)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// Start HTTP proxy
	p.StartHTTP(":4090")

	// Start HTTPS proxy; TODO: create TLS certificate for the proxy
	// p.StartHTTPS(":443")

}
