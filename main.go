package main

import (
	"log"
	"os"
	
	"aegis/ca"
	"aegis/proxy"
)

func main() {
	// Generate the root CA if not already there
	if _, err := os.Stat("certs/ca.crt"); os.IsNotExist(err) {
		log.Println("Generating root CA certificate...")
		if err := ca.GenerateRootCA(); err != nil {
			log.Fatalf("Failed to generate CA: %v", err)
		}
	}

	// Initialize the proxy
	p, err := proxy.NewProxy()
	if err != nil {
		log.Fatalf("Failed to initialize proxy: %v", err)
	}

	// Start the proxy
	if err := p.Start(":8080"); err != nil {
		log.Fatalf("Proxy failed: %v", err)
	}
}
