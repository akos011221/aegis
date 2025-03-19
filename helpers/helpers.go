package helpers

import (
	"net"
)

func HostWithoutPort(host string) string {
	// Splits a network address into host and port parts
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}
