// Command dnasrep is a self-contained DNAS replacement server for the
// Playstation 2. It bundles what previously required dnsmasq, a weak-cipher
// Apache/OpenSSL build and a set of PHP scripts into one Go binary:
//
//   - a DNS redirector for the gate1.{jp,eu,us}.dnas.playstation.org names
//   - a TLS server that presents the original per-region DNAS certificates
//   - the packet-replay logic of connect.php / others.php
//
// See README.md for the SSLv3/weak-cipher caveat.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

func main() {
	var (
		docroot   = flag.String("docroot", "./gate", "path to the DNAS document root (contains us-gw, eu-gw, ...)")
		certdir   = flag.String("certdir", "./certs", "directory holding cert-{jp,eu,us}[-key].pem")
		dnsAddr   = flag.String("dns", ":53", "UDP address for the DNS redirector (empty to disable)")
		upstream  = flag.String("upstream", "1.1.1.1:53", "upstream resolver for non-DNAS queries")
		redirect  = flag.String("redirect-ip", "", "IP that DNAS hostnames resolve to (default: auto-detected outbound IP)")
		defRegion = flag.String("default-region", "jp", "certificate region used when the client sends no SNI (jp/eu/us)")
		dnsConfig = flag.String("dns-config", "dns.config", "extra redirect rules file (\"<name> [ip]\" per line)")
	)
	var httpsAddrs stringList
	flag.Var(&httpsAddrs, "https", "TLS listen address(es), comma-separated or repeated (default :443)")
	var forceSucc successMode
	flag.Var(&forceSucc, "force-success", "use the gateway's success.raw: \"fallback\" for titles without a captured packet, \"always\" for every request (default \"off\")")
	var suffixes stringList
	flag.Var(&suffixes, "dns-suffix", "domain suffix(es) to redirect (default dnas.playstation.org)")
	flag.Parse()

	if len(httpsAddrs) == 0 {
		httpsAddrs = stringList{":443"}
	}
	if len(suffixes) == 0 {
		suffixes = stringList{"dnas.playstation.org"}
	}

	srv := &Server{
		DocRoot:       *docroot,
		defaultRegion: *defRegion,
		certs:         map[string]*tls.Certificate{},
		ForceSuccess:  forceSucc,
	}
	// When we are also the console's DNS, the gate1.<region> lookup that
	// precedes every DNAS connection tells us which certificate to present.
	if *dnsAddr != "" {
		srv.Hints = newRegionHints()
	}
	switch srv.ForceSuccess {
	case successFallback:
		log.Printf("force-success=fallback: titles without a captured packet are " +
			"answered with the gateway's success.raw instead of error.raw")
	case successAlways:
		log.Printf("force-success=always: every v2.5_i-connect/v2.5_others request " +
			"is answered with the gateway's success.raw, captured packets are ignored")
	}
	// The CA is sent after the leaf, as Apache did with SSLCertificateChainFile.
	caPath := filepath.Join(*certdir, "ca-cert.pem")
	chain, err := loadPEMCerts(caPath)
	if err != nil {
		log.Printf("warning: no CA chain (%v) - titles that verify the certificate chain will fail", err)
	}
	for _, region := range []string{"jp", "eu", "us"} {
		certPath := filepath.Join(*certdir, "cert-"+region+".pem")
		keyPath := filepath.Join(*certdir, "cert-"+region+"-key.pem")
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			log.Printf("warning: could not load %s certificate: %v", region, err)
			continue
		}
		appendChain(&cert, chain)
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			log.Printf("warning: could not parse %s certificate: %v", region, err)
			continue
		}
		srv.certs[region] = &cert
		log.Printf("loaded %s certificate: CN=%s, %s, valid until %s (%d-cert chain)",
			region, cert.Leaf.Subject.CommonName, cert.Leaf.SignatureAlgorithm,
			cert.Leaf.NotAfter.Format("2006-01-02"), len(cert.Certificate))
	}
	if len(srv.certs) == 0 {
		log.Fatalf("no certificates loaded from %s", *certdir)
	}
	if _, ok := srv.certs[srv.defaultRegion]; !ok {
		for r := range srv.certs {
			srv.defaultRegion = r
			break
		}
		log.Printf("default-region unavailable, falling back to %q", srv.defaultRegion)
	}

	// DNS redirector.
	if *dnsAddr != "" {
		ip := net.ParseIP(*redirect)
		if ip == nil {
			ip = outboundIP()
			log.Printf("redirect-ip auto-detected: %s", ip)
		}

		// dns.config rules come first so they take precedence over the built-in
		// -dns-suffix defaults for the same name. A missing file is only an
		// error when the operator explicitly pointed at one.
		var rules []dnsRule
		if extra, err := loadDNSConfig(*dnsConfig, ip); err == nil {
			rules = append(rules, extra...)
			log.Printf("dns: loaded %d rule(s) from %s", len(extra), *dnsConfig)
		} else if !os.IsNotExist(err) {
			log.Fatalf("dns: %v", err)
		} else if isFlagSet("dns-config") {
			log.Fatalf("dns: config file %s not found", *dnsConfig)
		}
		rules = append(rules, rulesFromSuffixes(suffixes, ip)...)
		rules = dedupeRules(rules)

		sortRulesLongestFirst(rules)
		dns := &DNSServer{Rules: rules, Upstream: *upstream, Hints: srv.Hints}
		go func() {
			if err := dns.listen(*dnsAddr); err != nil {
				log.Fatalf("dns: %v", err)
			}
		}()
	}

	log.Fatal(srv.listenTLS10(httpsAddrs))
}

// isFlagSet reports whether the named flag was provided on the command line.
func isFlagSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// outboundIP returns the local address the kernel would use to reach the
// internet, without actually sending anything.
func outboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return net.IPv4(127, 0, 0, 1)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}
