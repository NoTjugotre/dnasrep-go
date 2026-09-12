package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildV2Hello builds an SSLv2-compatible CLIENT-HELLO offering, among others,
// TLS_RSA_WITH_3DES_EDE_CBC_SHA, with the given 16-byte challenge.
func buildV2Hello(challenge []byte) []byte {
	specs := []byte{
		0x00, 0x00, 0x66, 0x00, 0x00, 0x16, 0x00, 0x00, 0x13, 0x00, 0x00, 0x0a,
		0x00, 0x00, 0x05, 0x00, 0x00, 0x04, 0x00, 0x00, 0x15, 0x00, 0x00, 0x12,
		0x00, 0x00, 0x09, 0x07, 0x00, 0xc0, 0x03, 0x00, 0x80, 0x01, 0x00, 0x80,
		0x06, 0x00, 0x40, 0x00, 0x00, 0x63, 0x00, 0x00, 0x65, 0x00, 0x00, 0x62,
		0x00, 0x00, 0x64, 0x00, 0x00, 0x14, 0x00, 0x00, 0x11, 0x00, 0x00, 0x08,
		0x00, 0x00, 0x06, 0x00, 0x00, 0x03, 0x04, 0x00, 0x80, 0x02, 0x00, 0x80,
		0x08, 0x00, 0x80,
	}
	body := []byte{hsClientHello, 0x03, 0x01}
	body = append(body, byte(len(specs)>>8), byte(len(specs))) // cipher-spec length
	body = append(body, 0x00, 0x00)                            // session-id length
	body = append(body, byte(len(challenge)>>8), byte(len(challenge)))
	body = append(body, specs...)
	body = append(body, challenge...)
	rec := []byte{0x80 | byte(len(body)>>8), byte(len(body))}
	return append(rec, body...)
}

// TestFullV2Handshake drives a complete PS2-style handshake (SSLv2 hello, RSA
// key exchange, 3DES-CBC records, Finished both ways) against the real server,
// then makes a DNAS "others" request over the encrypted channel — hashing the
// raw v2 body exactly as a PS2 does.
func TestFullV2Handshake(t *testing.T) {
	// --- server with a temp docroot holding one captured reply ---
	dir := t.TempDir()
	gw := filepath.Join(dir, "us-gw")
	if err := os.MkdirAll(filepath.Join(gw, "packets"), 0o755); err != nil {
		t.Fatal(err)
	}
	wantPayload := []byte("REPLAY-PACKET-CONTENTS")
	gameID := []byte{0x00, 0x44, 0xd7, 0x11, 0xbb, 0x7b, 0xfb, 0x3a}
	qrytype := []byte{0x01, 0x08, 0x00, 0x00}
	fname := hexs(gameID) + "_" + hexs(qrytype)
	if err := os.WriteFile(filepath.Join(gw, "packets", fname), wantPayload, 0o644); err != nil {
		t.Fatal(err)
	}

	cert := testRSACert(t)
	srv := &Server{DocRoot: dir, defaultRegion: "jp", certs: map[string]*tls.Certificate{"jp": &cert}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		srv.serveTLS10(conn)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	cli := &tls10Conn{conn: conn, br: bufio.NewReader(conn)}

	// --- 1) send v2 hello ---
	challenge := make([]byte, 16)
	rand.Read(challenge)
	hello := buildV2Hello(challenge)
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	transcript := append([]byte{}, hello[2:]...) // v2 body, as the PS2 hashes it

	clientRandom := append(make([]byte, 16), challenge...)

	// --- 2) read ServerHello, Certificate, ServerHelloDone ---
	var serverRandom []byte
	for {
		typ, body, err := cli.readRecord()
		if err != nil {
			t.Fatalf("reading server handshake: %v", err)
		}
		if typ != ctHandshake {
			t.Fatalf("unexpected record type %d", typ)
		}
		transcript = append(transcript, body...)
		switch body[0] {
		case hsServerHello:
			serverRandom = append([]byte{}, body[6:6+32]...)
		case hsServerHelloDone:
			goto keyExchange
		}
	}
keyExchange:
	if serverRandom == nil {
		t.Fatal("no ServerHello received")
	}

	// --- 3) ClientKeyExchange ---
	premaster := make([]byte, 48)
	rand.Read(premaster)
	premaster[0], premaster[1] = 0x03, 0x01
	pub := cert.PrivateKey.(*rsa.PrivateKey).Public().(*rsa.PublicKey)
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, pub, premaster)
	if err != nil {
		t.Fatal(err)
	}
	cke := []byte{hsClientKeyExchange, 0, 0, 0, byte(len(enc) >> 8), byte(len(enc))}
	cke = append(cke, enc...)
	putHSLen(cke)
	if err := cli.writeRecord(ctHandshake, cke); err != nil {
		t.Fatal(err)
	}
	transcript = append(transcript, cke...)

	// --- 4) derive keys (client perspective: read=server_write, write=client_write) ---
	master := prf10(premaster, []byte("master secret"),
		append(append([]byte{}, clientRandom...), serverRandom...), 48)
	setupClientKeys(cli, master, clientRandom, serverRandom)

	// --- 5) ChangeCipherSpec + client Finished ---
	if err := cli.writeRecord(ctChangeCipherSpec, []byte{1}); err != nil {
		t.Fatal(err)
	}
	cli.writeActive = true
	cli.writeSeq = 0
	clientVerify := prf10(master, []byte("client finished"), finishedHash(transcript), 12)
	clientFin := append([]byte{hsFinished, 0, 0, 12}, clientVerify...)
	if err := cli.writeRecord(ctHandshake, clientFin); err != nil {
		t.Fatal(err)
	}
	transcript = append(transcript, clientFin...)

	// --- 6) read server ChangeCipherSpec + Finished, verify ---
	typ, _, err := cli.readRecord()
	if err != nil || typ != ctChangeCipherSpec {
		t.Fatalf("expected server ChangeCipherSpec, got type %d err %v", typ, err)
	}
	cli.readActive = true
	cli.readSeq = 0
	typ, sfin, err := cli.readRecord()
	if err != nil || typ != ctHandshake || sfin[0] != hsFinished {
		t.Fatalf("expected server Finished, got type %d err %v", typ, err)
	}
	wantServerVerify := prf10(master, []byte("server finished"), finishedHash(transcript), 12)
	if !bytes.Equal(sfin[4:16], wantServerVerify) {
		t.Fatalf("server Finished mismatch:\n got  %x\n want %x", sfin[4:16], wantServerVerify)
	}

	// --- 7) DNAS "others" request over the encrypted channel ---
	reqBody := make([]byte, 0x1b+8)
	copy(reqBody[0:4], qrytype)
	copy(reqBody[0x1b:], gameID)
	req := []byte("POST /us-gw/v2.5_others HTTP/1.1\r\nHost: gate1.us.dnas.playstation.org\r\n")
	req = append(req, []byte("Content-Length: "+itoa(len(reqBody))+"\r\n\r\n")...)
	req = append(req, reqBody...)
	if err := cli.writeRecord(ctApplicationData, req); err != nil {
		t.Fatal(err)
	}

	typ, resp, err := cli.readRecord()
	if err != nil || typ != ctApplicationData {
		t.Fatalf("expected application data response, got type %d err %v", typ, err)
	}
	if !bytes.Contains(resp, []byte("HTTP/1.0 200 OK")) {
		t.Fatalf("response missing status line: %q", resp)
	}
	if !bytes.Contains(resp, wantPayload) {
		t.Fatalf("response missing replay payload.\nresponse: %q", resp)
	}
	if !bytes.Contains(resp, []byte("Content-Type: image/gif")) {
		t.Fatalf("response missing gif content-type: %q", resp)
	}
}

// setupClientKeys mirrors Server.setupKeys but from the client's perspective.
func setupClientKeys(c *tls10Conn, master, clientRandom, serverRandom []byte) {
	kb := prf10(master, []byte("key expansion"),
		append(append([]byte{}, serverRandom...), clientRandom...), 2*macLen+2*keyLen+2*ivLen)
	clientMAC := kb[0:macLen]
	serverMAC := kb[macLen : 2*macLen]
	cKey := kb[2*macLen : 2*macLen+keyLen]
	sKey := kb[2*macLen+keyLen : 2*macLen+2*keyLen]
	clientIV := kb[2*macLen+2*keyLen : 2*macLen+2*keyLen+ivLen]
	serverIV := kb[2*macLen+2*keyLen+ivLen : 2*macLen+2*keyLen+2*ivLen]
	c.writeMAC = clientMAC
	c.readMAC = serverMAC
	c.writeIV = append([]byte{}, clientIV...)
	c.readIV = append([]byte{}, serverIV...)
	c.writeCipher = must3DES(cKey)
	c.readCipher = must3DES(sKey)
}

func must3DES(key []byte) cipher.Block {
	b, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	return b
}

func hexs(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0xf]
	}
	return string(out)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// testRSACert generates a self-signed RSA certificate for the tests.
func testRSACert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gate1.us.dnas.playstation.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestChainIsSent checks that a CA appended with appendChain ends up in the
// Certificate message after the leaf, that duplicates are dropped, and that the
// client can parse the two-certificate list.
func TestChainIsSent(t *testing.T) {
	leaf := testRSACert(t)
	ca := testRSACert(t)
	appendChain(&leaf, ca.Certificate)
	appendChain(&leaf, ca.Certificate) // second call must not duplicate
	appendChain(&leaf, leaf.Certificate[:1])
	if len(leaf.Certificate) != 2 {
		t.Fatalf("chain has %d certs, want 2", len(leaf.Certificate))
	}

	msg := buildCertificate(leaf.Certificate)
	if msg[0] != hsCertificate {
		t.Fatalf("type = %d", msg[0])
	}
	listLen := int(msg[4])<<16 | int(msg[5])<<8 | int(msg[6])
	if listLen != len(msg)-7 {
		t.Fatalf("certificate_list length %d, want %d", listLen, len(msg)-7)
	}
	var got [][]byte
	for p := msg[7:]; len(p) > 0; {
		n := int(p[0])<<16 | int(p[1])<<8 | int(p[2])
		got = append(got, p[3:3+n])
		p = p[3+n:]
	}
	if len(got) != 2 || !bytes.Equal(got[0], leaf.Certificate[0]) || !bytes.Equal(got[1], ca.Certificate[0]) {
		t.Fatalf("parsed %d certs, order/content wrong", len(got))
	}
}

func TestLoadPEMCertsBundledCA(t *testing.T) {
	certs, err := loadPEMCerts("certs/ca-cert.pem")
	if err != nil {
		t.Skipf("bundled CA not available: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	c, err := x509.ParseCertificate(certs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsCA {
		t.Errorf("%s is not a CA certificate", c.Subject)
	}
}

// TestAlertAfterServerHelloDoneIsDecoded drives the handshake up to the
// server's flight and then answers with a fatal alert, as a title that rejects
// the certificate would. The logged error must name the alert.
func TestAlertAfterServerHelloDoneIsDecoded(t *testing.T) {
	cert := testRSACert(t)
	srv := &Server{DocRoot: t.TempDir(), defaultRegion: "jp", certs: map[string]*tls.Certificate{"jp": &cert}}

	client, server := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.handshakeAndServe(&tls10Conn{conn: server, br: bufio.NewReader(server)})
	}()

	challenge := make([]byte, 16)
	rand.Read(challenge)
	if _, err := client.Write(buildV2Hello(challenge)); err != nil {
		t.Fatal(err)
	}
	cli := &tls10Conn{conn: client, br: bufio.NewReader(client)}
	for {
		typ, body, err := cli.readRecord()
		if err != nil {
			t.Fatalf("reading server flight: %v", err)
		}
		if typ == ctHandshake && body[0] == hsServerHelloDone {
			break
		}
	}
	// fatal unknown_ca
	if err := cli.writeRecord(ctAlert, []byte{2, 48}); err != nil {
		t.Fatal(err)
	}
	client.Close()

	err := <-errCh
	if err == nil {
		t.Fatal("handshake succeeded, want an error")
	}
	for _, want := range []string{"expected ClientKeyExchange", "fatal alert 48 (unknown_ca)", "SSLv2-compat", "version 3.1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}
