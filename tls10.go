package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// This is a deliberately minimal, single-purpose TLS 1.0 server. Go's
// crypto/tls cannot talk to a PS2 DNAS client for two reasons: it rejects the
// SSLv2-compatible CLIENT-HELLO framing outright, and — even if that were
// bridged — the PS2 folds the *raw SSLv2 hello body* into its handshake hash
// (verified against a real capture), whereas crypto/tls always hashes the v3
// ClientHello it parsed. That mismatch makes the Finished MAC fail.
//
// So we implement just enough of TLS 1.0 ourselves to control the transcript:
// one cipher suite (TLS_RSA_WITH_3DES_EDE_CBC_SHA, 0x000a, which the PS2
// offers), RSA key exchange, and the SSLv2/v3 hello handling. Every primitive
// here (PRF, key expansion, 3DES-CBC records, HMAC-SHA1, Finished) was checked
// against a captured PS2 handshake plus the server private key.

const (
	ctChangeCipherSpec = 20
	ctAlert            = 21
	ctHandshake        = 22
	ctApplicationData  = 23

	hsClientHello       = 1
	hsServerHello       = 2
	hsCertificate       = 11
	hsServerHelloDone   = 14
	hsClientKeyExchange = 16
	hsFinished          = 20

	cipherRSA3DES = 0x000a // TLS_RSA_WITH_3DES_EDE_CBC_SHA

	macLen   = 20 // HMAC-SHA1
	keyLen   = 24 // 3DES-EDE
	ivLen    = 8  // DES block
	blockLen = 8
)

var tls10Version = []byte{0x03, 0x01}

// ---- PRF (TLS 1.0: P_MD5(S1) XOR P_SHA1(S2)) ----

func pHash(newHash func() hash.Hash, secret, seed []byte, n int) []byte {
	h := hmac.New(newHash, secret)
	h.Write(seed)
	a := h.Sum(nil)
	var out []byte
	for len(out) < n {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		out = append(out, h.Sum(nil)...)
		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
	return out[:n]
}

func prf10(secret, label, seed []byte, n int) []byte {
	ls := append(append([]byte{}, label...), seed...)
	half := (len(secret) + 1) / 2
	s1 := secret[:half]
	s2 := secret[len(secret)-half:]
	a := pHash(md5.New, s1, ls, n)
	b := pHash(sha1.New, s2, ls, n)
	out := make([]byte, n)
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// finishedHash returns MD5(transcript) || SHA1(transcript), the seed the TLS
// 1.0 PRF uses for the Finished verify_data.
func finishedHash(transcript []byte) []byte {
	m := md5.Sum(transcript)
	s := sha1.Sum(transcript)
	return append(m[:], s[:]...)
}

// tls10Conn is the per-connection record-layer state.
type tls10Conn struct {
	conn net.Conn
	br   *bufio.Reader

	transcript []byte // concatenated handshake messages (bodies, no record headers)
	helloInfo  string // one-line summary of the ClientHello, for logs
	helloSpecs string // the offered cipher specs/suites as hex, for logs
	certInfo   string // CN and validity of the certificate we presented

	readActive, writeActive bool
	readSeq, writeSeq       uint64
	readCipher, writeCipher cipher.Block
	readIV, writeIV         []byte
	readMAC, writeMAC       []byte

	plainBuf []byte // decrypted application data not yet consumed
}

// readRecord reads one TLS record and returns its content type and plaintext
// fragment (decrypting when the read side is active).
func (c *tls10Conn) readRecord() (byte, []byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c.br, hdr); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[3:5]))
	if length > 1<<14+2048 {
		return 0, nil, errors.New("tls: record too large")
	}
	frag := make([]byte, length)
	if _, err := io.ReadFull(c.br, frag); err != nil {
		return 0, nil, err
	}
	if !c.readActive {
		return hdr[0], frag, nil
	}
	content, err := c.decrypt(hdr[0], frag)
	if err != nil {
		return 0, nil, err
	}
	return hdr[0], content, nil
}

func (c *tls10Conn) decrypt(contentType byte, frag []byte) ([]byte, error) {
	if len(frag) < blockLen || len(frag)%blockLen != 0 {
		return nil, errors.New("tls: bad CBC record length")
	}
	plain := make([]byte, len(frag))
	cbc := cipher.NewCBCDecrypter(c.readCipher, c.readIV)
	cbc.CryptBlocks(plain, frag)
	c.readIV = append([]byte{}, frag[len(frag)-blockLen:]...) // TLS 1.0 IV chaining

	padLen := int(plain[len(plain)-1]) + 1
	if padLen > len(plain)-macLen {
		return nil, errors.New("tls: bad padding")
	}
	rec := plain[:len(plain)-padLen]
	if len(rec) < macLen {
		return nil, errors.New("tls: record shorter than MAC")
	}
	content := rec[:len(rec)-macLen]
	gotMAC := rec[len(rec)-macLen:]

	wantMAC := c.recordMAC(c.readMAC, c.readSeq, contentType, content)
	if subtle.ConstantTimeCompare(gotMAC, wantMAC) != 1 {
		return nil, errors.New("tls: bad record MAC")
	}
	c.readSeq++
	return content, nil
}

func (c *tls10Conn) writeRecord(contentType byte, content []byte) error {
	var payload []byte
	if !c.writeActive {
		payload = content
	} else {
		mac := c.recordMAC(c.writeMAC, c.writeSeq, contentType, content)
		plain := append(append([]byte{}, content...), mac...)
		padLen := blockLen - (len(plain) % blockLen)
		if padLen == 0 {
			padLen = blockLen
		}
		for i := 0; i < padLen; i++ {
			plain = append(plain, byte(padLen-1))
		}
		payload = make([]byte, len(plain))
		cbc := cipher.NewCBCEncrypter(c.writeCipher, c.writeIV)
		cbc.CryptBlocks(payload, plain)
		c.writeIV = append([]byte{}, payload[len(payload)-blockLen:]...)
		c.writeSeq++
	}
	rec := make([]byte, 0, 5+len(payload))
	rec = append(rec, contentType, tls10Version[0], tls10Version[1])
	rec = append(rec, byte(len(payload)>>8), byte(len(payload)))
	rec = append(rec, payload...)
	_, err := c.conn.Write(rec)
	return err
}

// recordMAC = HMAC-SHA1(key, seq || type || version || len || content).
func (c *tls10Conn) recordMAC(key []byte, seq uint64, contentType byte, content []byte) []byte {
	var hdr [13]byte
	binary.BigEndian.PutUint64(hdr[0:8], seq)
	hdr[8] = contentType
	hdr[9] = tls10Version[0]
	hdr[10] = tls10Version[1]
	binary.BigEndian.PutUint16(hdr[11:13], uint16(len(content)))
	h := hmac.New(sha1.New, key)
	h.Write(hdr[:])
	h.Write(content)
	return h.Sum(nil)
}

// writeHandshake sends a handshake message and folds it into the transcript.
func (c *tls10Conn) writeHandshake(msg []byte) error {
	c.transcript = append(c.transcript, msg...)
	return c.writeRecord(ctHandshake, msg)
}

// ---- handshake ----

func (s *Server) serveTLS10(raw net.Conn) {
	defer raw.Close()
	c := &tls10Conn{conn: raw, br: bufio.NewReader(raw)}
	if err := s.handshakeAndServe(c); err != nil && err != io.EOF {
		log.Printf("tls: %s handshake/serve: %v", clientIP(raw.RemoteAddr().String()), err)
	}
}

func (s *Server) handshakeAndServe(c *tls10Conn) error {
	ip := clientIP(c.conn.RemoteAddr().String())
	cert, certSource := s.certFor(ip)
	priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return errors.New("tls: server key is not RSA")
	}
	c.certInfo = "presented " + certSource
	if cert.Leaf != nil {
		c.certInfo = fmt.Sprintf("presented %s: CN=%s, %s, valid %s..%s", certSource, cert.Leaf.Subject.CommonName,
			cert.Leaf.SignatureAlgorithm, cert.Leaf.NotBefore.Format("2006-01-02"), cert.Leaf.NotAfter.Format("2006-01-02"))
	}

	// 1) ClientHello (SSLv2-compatible or v3). clientRandom is what both sides
	//    feed into key derivation; chMsg is what goes into the transcript.
	clientRandom, err := c.readClientHello()
	if err != nil {
		return fmt.Errorf("read ClientHello: %w", err)
	}
	log.Printf("tls: %s %s; using %s", ip, c.helloInfo, certSource)

	// 2) ServerHello with a fresh random.
	serverRandom := make([]byte, 32)
	if _, err := rand.Read(serverRandom); err != nil {
		return err
	}
	sh := buildServerHello(serverRandom)
	if err := c.writeHandshake(sh); err != nil {
		return err
	}

	// 3) Certificate + ServerHelloDone.
	if err := c.writeHandshake(buildCertificate(cert.Certificate)); err != nil {
		return err
	}
	if err := c.writeHandshake([]byte{hsServerHelloDone, 0, 0, 0}); err != nil {
		return err
	}

	// 4) ClientKeyExchange -> premaster secret.
	typ, body, err := c.readRecord()
	if err != nil {
		return err
	}
	if typ != ctHandshake || len(body) < 4 || body[0] != hsClientKeyExchange {
		return c.unexpected("ClientKeyExchange", typ, body)
	}
	c.transcript = append(c.transcript, body...)
	premaster, err := decryptPremaster(priv, body)
	if err != nil {
		return err
	}

	master := prf10(premaster, []byte("master secret"),
		append(append([]byte{}, clientRandom...), serverRandom...), 48)
	c.setupKeys(master, clientRandom, serverRandom)

	// 5) ChangeCipherSpec + client Finished.
	typ, body, err = c.readRecord()
	if err != nil {
		return err
	}
	if typ != ctChangeCipherSpec {
		return c.unexpected("ChangeCipherSpec", typ, body)
	}
	c.readActive = true
	c.readSeq = 0

	// transcript hash BEFORE the client Finished is added.
	clientVerify := prf10(master, []byte("client finished"), finishedHash(c.transcript), 12)

	typ, fin, err := c.readRecord()
	if err != nil {
		return err
	}
	if typ != ctHandshake || len(fin) != 16 || fin[0] != hsFinished {
		return c.unexpected("Finished", typ, fin)
	}
	if subtle.ConstantTimeCompare(fin[4:16], clientVerify) != 1 {
		return errors.New("tls: client Finished mismatch")
	}
	c.transcript = append(c.transcript, fin...)

	// 6) Our ChangeCipherSpec + server Finished.
	if err := c.writeRecord(ctChangeCipherSpec, []byte{1}); err != nil {
		return err
	}
	c.writeActive = true
	c.writeSeq = 0
	serverVerify := prf10(master, []byte("server finished"), finishedHash(c.transcript), 12)
	serverFin := append([]byte{hsFinished, 0, 0, 12}, serverVerify...)
	if err := c.writeRecord(ctHandshake, serverFin); err != nil {
		return err
	}

	// 7) Application data: read the HTTP request, dispatch, reply.
	return s.serveHTTP(c)
}

// readClientHello handles both the SSLv2-compatible hello and a normal v3
// ClientHello, appends the correct bytes to the transcript, and returns the
// derived client_random.
func (c *tls10Conn) readClientHello() ([]byte, error) {
	first, err := c.br.Peek(1)
	if err != nil {
		return nil, err
	}

	if first[0]&0x80 != 0 {
		// SSLv2-compatible CLIENT-HELLO: 2-byte length header + body.
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(c.br, hdr); err != nil {
			return nil, err
		}
		recLen := int(hdr[0]&0x7f)<<8 | int(hdr[1])
		body := make([]byte, recLen)
		if _, err := io.ReadFull(c.br, body); err != nil {
			return nil, err
		}
		if len(body) < 9 || body[0] != hsClientHello {
			return nil, errors.New("tls: malformed SSLv2 hello")
		}
		// The PS2 hashes the raw v2 hello *body* — this is the whole reason for
		// this file. (Verified against a real capture.)
		c.transcript = append(c.transcript, body...)

		csl := int(binary.BigEndian.Uint16(body[3:5]))
		sil := int(binary.BigEndian.Uint16(body[5:7]))
		cl := int(binary.BigEndian.Uint16(body[7:9]))
		if 9+csl+sil+cl > len(body) {
			return nil, errors.New("tls: SSLv2 hello field overflow")
		}
		c.helloInfo = fmt.Sprintf("ClientHello: SSLv2-compat, version %d.%d, %d cipher specs, %d-byte challenge",
			body[1], body[2], csl/3, cl)
		c.helloSpecs = hex.EncodeToString(body[9 : 9+csl])
		if !offersCipher(body[9:9+csl], true) {
			return nil, fmt.Errorf("tls: client does not offer TLS_RSA_WITH_3DES_EDE_CBC_SHA (%s)", c.helloInfo)
		}
		challenge := body[9+csl+sil : 9+csl+sil+cl]
		random := make([]byte, 32)
		if cl > 32 {
			challenge = challenge[cl-32:]
			cl = 32
		}
		copy(random[32-cl:], challenge) // left-zero-padded, as in key derivation
		return random, nil
	}

	// Normal v3 ClientHello handshake record.
	typ, body, err := c.readRecord()
	if err != nil {
		return nil, err
	}
	if typ != ctHandshake || len(body) < 4 || body[0] != hsClientHello {
		return nil, errors.New("tls: expected ClientHello")
	}
	c.transcript = append(c.transcript, body...)

	p := body[4:] // skip handshake header
	if len(p) < 34 {
		return nil, errors.New("tls: short ClientHello")
	}
	random := append([]byte{}, p[2:34]...)
	off := 34
	sidLen := int(p[off])
	off += 1 + sidLen
	if off+2 > len(p) {
		return nil, errors.New("tls: malformed ClientHello")
	}
	csLen := int(binary.BigEndian.Uint16(p[off : off+2]))
	off += 2
	if off+csLen > len(p) {
		return nil, errors.New("tls: malformed ClientHello suites")
	}
	c.helloInfo = fmt.Sprintf("ClientHello: v3, version %d.%d, %d cipher suites, %d-byte session id",
		p[0], p[1], csLen/2, sidLen)
	c.helloSpecs = hex.EncodeToString(p[off : off+csLen])
	if !offersCipher(p[off:off+csLen], false) {
		return nil, fmt.Errorf("tls: client does not offer TLS_RSA_WITH_3DES_EDE_CBC_SHA (%s)", c.helloInfo)
	}
	return random, nil
}

// unexpected builds the error for a record that is not the handshake message
// we were waiting for. Alerts are decoded, because that is where a title tells
// us *why* it gave up (unknown_ca, certificate_expired, protocol_version, ...).
// The cipher list fingerprints the client's TLS stack and the certificate line
// shows what a rejecting title actually looked at (region, algorithm, dates).
func (c *tls10Conn) unexpected(want string, typ byte, body []byte) error {
	return fmt.Errorf("tls: expected %s, got %s (%s; specs %s; %s)",
		want, describeRecord(typ, body), c.helloInfo, c.helloSpecs, c.certInfo)
}

// alertNames maps TLS 1.0 / SSL 3.0 alert descriptions to their names.
var alertNames = map[byte]string{
	0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
	21: "decryption_failed", 22: "record_overflow", 30: "decompression_failure",
	40: "handshake_failure", 41: "no_certificate", 42: "bad_certificate",
	43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
	46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
	49: "access_denied", 50: "decode_error", 51: "decrypt_error",
	60: "export_restriction", 70: "protocol_version", 71: "insufficient_security",
	80: "internal_error", 90: "user_canceled", 100: "no_renegotiation",
}

var handshakeNames = map[byte]string{
	hsClientHello: "ClientHello", hsServerHello: "ServerHello", hsCertificate: "Certificate",
	hsServerHelloDone: "ServerHelloDone", hsClientKeyExchange: "ClientKeyExchange",
	hsFinished: "Finished", 0: "HelloRequest", 12: "ServerKeyExchange",
	13: "CertificateRequest", 15: "CertificateVerify",
}

// describeRecord renders a record for log messages.
func describeRecord(typ byte, body []byte) string {
	switch typ {
	case ctAlert:
		if len(body) < 2 {
			return fmt.Sprintf("truncated alert %x", body)
		}
		level := "warning"
		if body[0] == 2 {
			level = "fatal"
		}
		name := alertNames[body[1]]
		if name == "" {
			name = "unknown"
		}
		return fmt.Sprintf("%s alert %d (%s)", level, body[1], name)
	case ctHandshake:
		if len(body) == 0 {
			return "empty handshake record"
		}
		name := handshakeNames[body[0]]
		if name == "" {
			name = "unknown"
		}
		return fmt.Sprintf("handshake %d (%s), %d bytes", body[0], name, len(body))
	case ctChangeCipherSpec:
		return "ChangeCipherSpec"
	case ctApplicationData:
		return fmt.Sprintf("%d bytes of application data", len(body))
	}
	return fmt.Sprintf("record type %d, %d bytes", typ, len(body))
}

// offersCipher reports whether the cipher list includes 0x000a. v2 lists are
// 3-byte specs (keep those with a zero lead byte); v3 lists are 2-byte suites.
func offersCipher(list []byte, v2 bool) bool {
	if v2 {
		for i := 0; i+3 <= len(list); i += 3 {
			if list[i] == 0 && list[i+1] == 0x00 && list[i+2] == 0x0a {
				return true
			}
		}
		return false
	}
	for i := 0; i+2 <= len(list); i += 2 {
		if list[i] == 0x00 && list[i+1] == 0x0a {
			return true
		}
	}
	return false
}

func buildServerHello(serverRandom []byte) []byte {
	b := []byte{hsServerHello, 0, 0, 0}
	b = append(b, tls10Version...)
	b = append(b, serverRandom...)
	b = append(b, 0x00)                                        // session_id length 0
	b = append(b, byte(cipherRSA3DES>>8), byte(cipherRSA3DES)) // cipher suite
	b = append(b, 0x00)                                        // compression: null
	putHSLen(b)
	return b
}

func buildCertificate(chain [][]byte) []byte {
	var certs []byte
	for _, der := range chain {
		certs = append(certs, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
		certs = append(certs, der...)
	}
	b := []byte{hsCertificate, 0, 0, 0}
	b = append(b, byte(len(certs)>>16), byte(len(certs)>>8), byte(len(certs)))
	b = append(b, certs...)
	putHSLen(b)
	return b
}

// putHSLen fills in the 3-byte handshake length field of msg in place.
func putHSLen(msg []byte) {
	n := len(msg) - 4
	msg[1] = byte(n >> 16)
	msg[2] = byte(n >> 8)
	msg[3] = byte(n)
}

func decryptPremaster(priv *rsa.PrivateKey, cke []byte) ([]byte, error) {
	p := cke[4:]
	if len(p) < 2 {
		return nil, errors.New("tls: short ClientKeyExchange")
	}
	encLen := int(binary.BigEndian.Uint16(p[0:2]))
	if 2+encLen > len(p) {
		return nil, errors.New("tls: bad ClientKeyExchange length")
	}
	enc := p[2 : 2+encLen]

	// Bleichenbacher countermeasure: on any failure, use a random premaster so
	// the handshake fails only later at Finished, indistinguishably.
	premaster := make([]byte, 48)
	rand.Read(premaster)
	premaster[0] = tls10Version[0]
	premaster[1] = tls10Version[1]
	if dec, err := rsa.DecryptPKCS1v15(rand.Reader, priv, enc); err == nil && len(dec) == 48 {
		// Keep the client's version bytes only if they look sane; copy the rest.
		copy(premaster[2:], dec[2:])
		premaster[0] = dec[0]
		premaster[1] = dec[1]
	}
	return premaster, nil
}

func (c *tls10Conn) setupKeys(master, clientRandom, serverRandom []byte) {
	kb := prf10(master, []byte("key expansion"),
		append(append([]byte{}, serverRandom...), clientRandom...), 2*macLen+2*keyLen+2*ivLen)
	c.readMAC = kb[0:macLen]
	c.writeMAC = kb[macLen : 2*macLen]
	cKey := kb[2*macLen : 2*macLen+keyLen]
	sKey := kb[2*macLen+keyLen : 2*macLen+2*keyLen]
	c.readIV = append([]byte{}, kb[2*macLen+2*keyLen:2*macLen+2*keyLen+ivLen]...)
	c.writeIV = append([]byte{}, kb[2*macLen+2*keyLen+ivLen:2*macLen+2*keyLen+2*ivLen]...)
	c.readCipher, _ = des.NewTripleDESCipher(cKey)
	c.writeCipher, _ = des.NewTripleDESCipher(sKey)
}

// ---- application layer (HTTP over the encrypted channel) ----

func (c *tls10Conn) readAppData() ([]byte, error) {
	if len(c.plainBuf) > 0 {
		b := c.plainBuf
		c.plainBuf = nil
		return b, nil
	}
	for {
		typ, data, err := c.readRecord()
		if err != nil {
			return nil, err
		}
		switch typ {
		case ctApplicationData:
			return data, nil
		case ctAlert:
			return nil, io.EOF
		default:
			// ignore anything unexpected
		}
	}
}

func (s *Server) serveHTTP(c *tls10Conn) error {
	// Accumulate until we have the full request (headers + Content-Length body).
	var buf []byte
	for {
		chunk, err := c.readAppData()
		if err != nil {
			return err
		}
		buf = append(buf, chunk...)
		if complete, req := parseHTTPRequest(buf); complete {
			log.Printf("https: %s %s %s (%d-byte body)",
				clientIP(c.conn.RemoteAddr().String()), req.method, req.path, len(req.body))
			resp := s.dispatch(req)
			return c.writeRecord(ctApplicationData, resp)
		}
	}
}

type httpRequest struct {
	method string
	path   string
	body   []byte
}

// parseHTTPRequest returns (true, req) once the full request is buffered.
func parseHTTPRequest(buf []byte) (bool, httpRequest) {
	idx := bytes.Index(buf, []byte("\r\n\r\n"))
	if idx < 0 {
		return false, httpRequest{}
	}
	head := string(buf[:idx])
	lines := strings.Split(head, "\r\n")
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return false, httpRequest{}
	}
	contentLen := 0
	for _, l := range lines[1:] {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "content-length") {
			contentLen, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	bodyStart := idx + 4
	if len(buf)-bodyStart < contentLen {
		return false, httpRequest{}
	}
	return true, httpRequest{
		method: parts[0],
		path:   parts[1],
		body:   buf[bodyStart : bodyStart+contentLen],
	}
}

// dispatch routes the request the same way Apache + the PHP scripts did.
func (s *Server) dispatch(req httpRequest) []byte {
	base := path.Base(req.path)
	switch base {
	// v2.1_d-connect is the HDD (PSBBN / HDD-installed titles) flavour of the
	// connect endpoint; same query layout and reply pipeline as v2.5_i-connect.
	case "v2.5_i-connect", "v2.1_d-connect", "v2.5_others":
		gwDir, ok := s.gwDirFor(req.path)
		if !ok {
			return httpResponse("image/gif", nil)
		}
		if s.ForceSuccess == successAlways {
			log.Printf("https: force-success: answering %s with success.raw", req.path)
			return httpResponse("image/gif", s.successRaw(gwDir))
		}
		if base == "v2.5_others" {
			return httpResponse("image/gif", s.othersReply(gwDir, req.body))
		}
		return httpResponse("image/gif", s.connectReply(gwDir, req.body))
	default:
		return s.serveStatic(req.path)
	}
}

// serveStatic serves bbnavi HTML/XML and other static assets from the docroot.
func (s *Server) serveStatic(urlPath string) []byte {
	clean := path.Clean("/" + urlPath)
	full := filepath.Join(s.DocRoot, filepath.FromSlash(clean))
	rel, err := filepath.Rel(s.DocRoot, full)
	if err != nil || strings.HasPrefix(rel, "..") {
		return httpStatus("404 Not Found")
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return httpStatus("404 Not Found")
	}
	ct := "application/octet-stream"
	switch strings.ToLower(filepath.Ext(full)) {
	case ".xml":
		ct = "text/xml"
	case ".html", ".htm":
		ct = "text/html"
	}
	return httpResponse(ct, data)
}

func httpResponse(contentType string, body []byte) []byte {
	head := fmt.Sprintf("HTTP/1.0 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		contentType, len(body))
	return append([]byte(head), body...)
}

func httpStatus(status string) []byte {
	return []byte(fmt.Sprintf("HTTP/1.0 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status))
}

// ---- listener ----

// listenTLS10 accepts raw TCP connections and drives the minimal TLS 1.0
// server on each. It replaces the crypto/tls + net/http stack for the DNAS
// endpoints.
func (s *Server) listenTLS10(addrs []string) error {
	errCh := make(chan error, len(addrs))
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		log.Printf("https: listening on %s (custom TLS 1.0)", addr)
		go func(l net.Listener) {
			for {
				conn, err := l.Accept()
				if err != nil {
					errCh <- err
					return
				}
				log.Printf("https: connection from %s", clientIP(conn.RemoteAddr().String()))
				go s.serveTLS10(conn)
			}
		}(ln)
	}
	return <-errCh
}
