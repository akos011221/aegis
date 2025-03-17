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

	// Start it
	if err := p.Start(config.ListenAddr); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}
