package helpers

import (
	"net"
)

func HostWithoutPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}
