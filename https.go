package main

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net"
	"os"
)

// Server holds the shared state for the DNAS handler.
type Server struct {
	DocRoot string

	// certs maps a region key ("jp","eu","us") to a loaded certificate.
	certs map[string]*tls.Certificate
	// defaultRegion selects the certificate to present. PS2 clients send no SNI,
	// so a single region is served per listener (see README for multi-IP setups).
	defaultRegion string

	// ForceSuccess selects how the gateway's success.raw is used: not at all
	// (successOff), only for titles without a captured packet (successFallback),
	// or for every replay request (successAlways). An experimental workaround
	// for titles that were never captured for the DNASforever project; see
	// README ("Force-success workaround").
	ForceSuccess successMode
}

// clientIP strips the port from a "host:port" address, returning just the host.
func clientIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// loadPEMCerts returns the DER bytes of every CERTIFICATE block in a PEM file.
func loadPEMCerts(path string) ([][]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs [][]byte
	for {
		var blk *pem.Block
		blk, raw = pem.Decode(raw)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			certs = append(certs, blk.Bytes)
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("no CERTIFICATE block found")
	}
	return certs, nil
}

// appendChain adds the CA certificate(s) to a leaf certificate's chain, the way
// Apache's SSLCertificateChainFile did in the original DNASrep setup. Titles
// that verify the chain need the (forged) VeriSign CA to be sent along;
// titles that don't simply ignore the extra certificate. CA certs already
// present in the leaf's PEM are not duplicated.
func appendChain(cert *tls.Certificate, chain [][]byte) {
	for _, ca := range chain {
		dup := false
		for _, have := range cert.Certificate {
			if string(have) == string(ca) {
				dup = true
				break
			}
		}
		if !dup {
			cert.Certificate = append(cert.Certificate, ca)
		}
	}
}
