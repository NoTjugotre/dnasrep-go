package main

import (
	"crypto/tls"
	"strings"
	"sync"
	"time"
)

// regionHints remembers, per client IP, which DNAS region a console last
// resolved. A PS2 always looks up gate1.<region>.dnas.playstation.org right
// before opening the TLS connection, and its hello carries no SNI - so that
// lookup is the only signal telling us which region's certificate the
// connection expects. Titles that check the certificate's CN against the
// hostname reject the wrong region with a certificate_unknown alert.
type regionHints struct {
	mu   sync.Mutex
	byIP map[string]regionHint
}

type regionHint struct {
	region string
	at     time.Time
}

func newRegionHints() *regionHints {
	return &regionHints{byIP: map[string]regionHint{}}
}

func (h *regionHints) set(ip, region string) {
	h.mu.Lock()
	h.byIP[ip] = regionHint{region: region, at: time.Now()}
	h.mu.Unlock()
}

func (h *regionHints) get(ip string) (regionHint, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.byIP[ip]
	return r, ok
}

// regionFromName extracts the region label from a DNAS hostname, e.g.
// "gate1.us.dnas.playstation.org" -> "us". Any host under
// <region>.dnas.playstation.org counts (ts01, dnns-p01, bbn01, ...).
func regionFromName(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	const suffix = ".dnas.playstation.org"
	if !strings.HasSuffix(name, suffix) {
		return "", false
	}
	rest := strings.TrimSuffix(name, suffix)
	if rest == "" {
		return "", false
	}
	region := rest[strings.LastIndexByte(rest, '.')+1:]
	if region == "" {
		return "", false
	}
	return region, true
}

// certFor picks the certificate for a connection from ip: the region the
// console resolved last, if we have a certificate for it, else the default.
// The returned string says which, for the log.
func (s *Server) certFor(ip string) (*tls.Certificate, string) {
	if s.Hints != nil {
		if h, ok := s.Hints.get(ip); ok {
			if cert, ok := s.certs[h.region]; ok {
				return cert, h.region + " certificate (DNS lookup " + time.Since(h.at).Round(time.Second).String() + " ago)"
			}
			return s.certs[s.defaultRegion], s.defaultRegion + " certificate (default; no certificate for DNS-resolved region " + h.region + ")"
		}
	}
	return s.certs[s.defaultRegion], s.defaultRegion + " certificate (default; no DNS lookup seen from this client)"
}
