package main

import (
	"crypto/tls"
	"net"
)

// Server holds the shared state for the DNAS handler.
type Server struct {
	DocRoot string

	// certs maps a region key ("jp","eu","us") to a loaded certificate.
	certs map[string]*tls.Certificate
	// defaultRegion selects the certificate to present. PS2 clients send no SNI,
	// so a single region is served per listener (see README for multi-IP setups).
	defaultRegion string
}

// clientIP strips the port from a "host:port" address, returning just the host.
func clientIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
