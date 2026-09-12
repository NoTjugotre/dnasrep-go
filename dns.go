package main

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"strings"
	"time"
)

// dnsRule redirects a hostname (or a whole domain suffix) to a fixed A-record
// answer.
type dnsRule struct {
	suffix string // lowercase, no trailing dot, e.g. "www01.kddi-mmbb.jp"
	ip     net.IP
}

// DNSServer is a tiny UDP forwarder: names matching a rule are answered with
// that rule's IP, everything else is proxied to an upstream resolver. This
// replaces the dnsmasq "address=/.../IP" entries, extended with a config file.
type DNSServer struct {
	Rules    []dnsRule // sorted most-specific (longest suffix) first
	Upstream string    // host:port of a normal resolver, e.g. 1.1.1.1:53
	// Hints records which DNAS region each client resolved last, so the TLS
	// side can present the matching certificate. Optional.
	Hints *regionHints
}

func (d *DNSServer) listen(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	log.Printf("dns: listening on %s (%d redirect rule(s))", addr, len(d.Rules))
	for _, r := range d.Rules {
		log.Printf("dns:   %s -> %s", r.suffix, r.ip)
	}
	buf := make([]byte, 512)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("dns: read: %v", err)
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go d.handle(pc, src, query)
	}
}

func (d *DNSServer) handle(pc net.PacketConn, src net.Addr, query []byte) {
	name, qtype, ok := parseQuestion(query)
	if ok && qtype == 1 { // qtype 1 == A
		if ip := d.lookup(name); ip != nil {
			if resp, err := buildAResponse(query, ip); err == nil {
				pc.WriteTo(resp, src)
				note := ""
				if region, ok := regionFromName(name); ok && d.Hints != nil {
					d.Hints.set(clientIP(src.String()), region)
					note = ", " + region + " region noted for " + clientIP(src.String())
				}
				log.Printf("dns: %s -> %s (redirected%s)", name, ip, note)
				return
			}
		}
	}
	// Not ours (or not an A query): forward upstream.
	if resp, err := d.forward(query); err == nil {
		pc.WriteTo(resp, src)
	} else {
		log.Printf("dns: forward %q: %v", name, err)
	}
}

// lookup returns the redirect IP for name, or nil if no rule matches. Rules are
// tried most-specific first so a per-host rule beats a broader suffix rule.
func (d *DNSServer) lookup(name string) net.IP {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, r := range d.Rules {
		if name == r.suffix || strings.HasSuffix(name, "."+r.suffix) {
			return r.ip
		}
	}
	return nil
}

func (d *DNSServer) forward(query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", d.Upstream, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, err
	}
	return resp[:n], nil
}

// parseQuestion extracts the QNAME and QTYPE of the first question.
func parseQuestion(msg []byte) (name string, qtype uint16, ok bool) {
	if len(msg) < 12 {
		return "", 0, false
	}
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	if qdcount < 1 {
		return "", 0, false
	}
	pos := 12
	var labels []string
	for {
		if pos >= len(msg) {
			return "", 0, false
		}
		l := int(msg[pos])
		pos++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 { // compression pointer not expected in a question
			return "", 0, false
		}
		if pos+l > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[pos:pos+l]))
		pos += l
	}
	if pos+4 > len(msg) {
		return "", 0, false
	}
	qtype = binary.BigEndian.Uint16(msg[pos : pos+2])
	return strings.Join(labels, "."), qtype, true
}

// buildAResponse turns a query into an authoritative single-answer A response.
func buildAResponse(query []byte, ip net.IP) ([]byte, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("redirect IP is not IPv4")
	}
	// The question section ends after QNAME + QTYPE(2) + QCLASS(2).
	qEnd := 12
	for {
		if qEnd >= len(query) {
			return nil, errors.New("malformed question")
		}
		l := int(query[qEnd])
		qEnd++
		if l == 0 {
			break
		}
		qEnd += l
	}
	qEnd += 4 // QTYPE + QCLASS
	if qEnd > len(query) {
		return nil, errors.New("truncated question")
	}

	resp := make([]byte, qEnd, qEnd+16)
	copy(resp, query[:qEnd])

	// Flags: QR=1, AA=1, keep RD, set RA. rcode 0.
	resp[2] = 0x81 | (query[2] & 0x01)         // QR + Opcode(0) + AA=1 + RD copied
	resp[3] = 0x80                             // RA=1, rcode 0
	binary.BigEndian.PutUint16(resp[6:8], 1)   // ANCOUNT = 1
	binary.BigEndian.PutUint16(resp[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(resp[10:12], 0) // ARCOUNT

	// Answer: name pointer to offset 12, type A, class IN, TTL, RDLENGTH, IP.
	ans := []byte{
		0xc0, 0x0c, // pointer to QNAME
		0x00, 0x01, // TYPE A
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x01, 0x2c, // TTL 300
		0x00, 0x04, // RDLENGTH
		ip4[0], ip4[1], ip4[2], ip4[3],
	}
	return append(resp, ans...), nil
}
