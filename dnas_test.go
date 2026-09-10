package main

import (
	"bytes"
	"crypto/des"
	"crypto/rand"
	"encoding/binary"
	"net"
	"os"
	"testing"
)

// encrypt3nManual is a literal, block-by-block re-implementation of the PHP
// encrypt3n() loop (single-DES encrypt-k1 / decrypt-k2 / encrypt-k3 with the
// previous ciphertext block chained back in). encrypt3n() in dnas.go collapses
// this into a stdlib 3DES-CBC call; this test proves the two agree.
func encrypt3nManual(data []byte, offset, length int, k1, k2, k3, seed []byte) []byte {
	c1, _ := des.NewCipher(k1)
	c2, _ := des.NewCipher(k2)
	c3, _ := des.NewCipher(k3)
	key := append([]byte(nil), seed...)
	out := append([]byte(nil), data...)
	for i := 0; i < length; i += 8 {
		dat := make([]byte, 8)
		for t := 0; t < 8; t++ {
			dat[t] = out[offset+i+t] ^ key[t]
		}
		enc := make([]byte, 8)
		c1.Encrypt(enc, dat)
		c2.Decrypt(enc, enc)
		c3.Encrypt(enc, enc)
		copy(out[offset+i:offset+i+8], enc)
		key = enc
	}
	return out
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEncrypt3nMatchesManual(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		data := randBytes(t, 0x148)
		k1, k2, k3, seed := randBytes(t, 8), randBytes(t, 8), randBytes(t, 8), randBytes(t, 8)

		want := encrypt3nManual(data, 0x28, 0x120, k1, k2, k3, seed)

		got := append([]byte(nil), data...)
		if _, err := encrypt3n(got, 0x28, 0x120, k1, k2, k3, seed); err != nil {
			t.Fatalf("encrypt3n: %v", err)
		}
		if !bytes.Equal(got[0x28:0x28+0x120], want[0x28:0x28+0x120]) {
			t.Fatalf("iter %d: encrypted region differs", iter)
		}
		// Bytes outside the region must be untouched.
		if !bytes.Equal(got[:0x28], data[:0x28]) {
			t.Fatalf("iter %d: bytes before region were modified", iter)
		}
	}
}

func TestEncrypt3nBadLength(t *testing.T) {
	data := make([]byte, 32)
	if _, err := encrypt3n(data, 0, 7, data[:8], data[:8], data[:8], data[:8]); err == nil {
		t.Fatal("expected error for non-block-multiple length")
	}
}

func TestConnectPipelineOrder(t *testing.T) {
	// Applying inner (0xc8/0x20) then envelope (0x28/0x120) must equal doing the
	// same two manual passes in the same order.
	data := randBytes(t, 0x148)
	req := randBytes(t, 0x48+0xec)
	k1, k2, k3, seed, err := deriveKeys(req)
	if err != nil {
		t.Fatal(err)
	}

	want := encrypt3nManual(data, 0xc8, 0x20, k1, k2, k3, seed)
	want = encrypt3nManual(want, 0x28, 0x120, envK1, envK2, envK3, envSeed)

	got := append([]byte(nil), data...)
	if _, err := encrypt3n(got, 0xc8, 0x20, k1, k2, k3, seed); err != nil {
		t.Fatal(err)
	}
	if _, err := encrypt3n(got, 0x28, 0x120, envK1, envK2, envK3, envSeed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("full connect pipeline differs from manual reference")
	}
}

func TestPacketName(t *testing.T) {
	req := make([]byte, 0x40)
	copy(req[0:4], []byte{0x01, 0x18, 0x00, 0x00})
	copy(req[0x2c:0x2c+8], []byte{0x00, 0x44, 0xd7, 0x11, 0xbb, 0x7b, 0xfb, 0x3a})
	name, ok := packetName(req, 0x2c)
	if !ok || name != "0044d711bb7bfb3a_01180000" {
		t.Fatalf("got %q ok=%v", name, ok)
	}
}

// forceSuccessDocRoot builds a throwaway docroot with one gateway directory
// holding a captured packet, error.raw and (optionally) success.raw.
func forceSuccessDocRoot(t *testing.T, withSuccess bool) string {
	t.Helper()
	root := t.TempDir()
	gw := root + "/us-gw"
	if err := os.MkdirAll(gw+"/packets", 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) {
		if err := os.WriteFile(gw+"/"+name, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("packets/0044d711bb7bfb3a_01180000", []byte("CAPTURED"))
	write("error.raw", []byte("ERROR"))
	if withSuccess {
		write("success.raw", []byte("SUCCESS"))
	}
	return root
}

// othersRequest is a minimal v2.5_others query for game 0044d711bb7bfb3a.
func othersRequest() httpRequest {
	body := make([]byte, 0x40)
	copy(body[0:4], []byte{0x01, 0x18, 0x00, 0x00})
	copy(body[0x1b:0x1b+8], []byte{0x00, 0x44, 0xd7, 0x11, 0xbb, 0x7b, 0xfb, 0x3a})
	return httpRequest{method: "POST", path: "/us-gw/v2.5_others", body: body}
}

// unknownRequest is othersRequest() for a game ID that has no capture.
func unknownRequest() httpRequest {
	req := othersRequest()
	copy(req.body[0x1b:0x1b+8], []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef})
	return req
}

func TestForceSuccessModes(t *testing.T) {
	root := forceSuccessDocRoot(t, true)
	connect := func(r httpRequest) httpRequest {
		r.path = "/us-gw/v2.5_i-connect"
		return r
	}

	cases := []struct {
		name string
		mode successMode
		req  httpRequest
		want string
	}{
		// off - the original behaviour, success.raw is never touched.
		{"off/captured", successOff, othersRequest(), "CAPTURED"},
		{"off/uncaptured", successOff, unknownRequest(), "ERROR"},

		// fallback - captured titles keep their real replies, only the
		// error.raw case is replaced.
		{"fallback/captured", successFallback, othersRequest(), "CAPTURED"},
		{"fallback/uncaptured", successFallback, unknownRequest(), "SUCCESS"},
		{"fallback/uncaptured i-connect", successFallback, connect(unknownRequest()), "SUCCESS"},

		// always - success.raw wins even where a capture exists.
		{"always/captured", successAlways, othersRequest(), "SUCCESS"},
		{"always/uncaptured", successAlways, unknownRequest(), "SUCCESS"},
		{"always/i-connect", successAlways, connect(othersRequest()), "SUCCESS"},
	}
	for _, tc := range cases {
		s := &Server{DocRoot: root, ForceSuccess: tc.mode}
		if got := s.dispatch(tc.req); !bytes.HasSuffix(got, []byte(tc.want)) {
			t.Errorf("%s: got %q, want %s", tc.name, got, tc.want)
		}
	}
}

// A malformed (too short) body is not an uncaptured title, so it keeps getting
// error.raw even in fallback mode.
func TestForceSuccessFallbackKeepsErrorForMalformed(t *testing.T) {
	req := othersRequest()
	req.body = req.body[:4]
	s := &Server{DocRoot: forceSuccessDocRoot(t, true), ForceSuccess: successFallback}
	if got := s.dispatch(req); !bytes.HasSuffix(got, []byte("ERROR")) {
		t.Fatalf("malformed body: got %q, want error.raw", got)
	}
}

func TestForceSuccessFallsBackToError(t *testing.T) {
	for _, mode := range []successMode{successFallback, successAlways} {
		s := &Server{DocRoot: forceSuccessDocRoot(t, false), ForceSuccess: mode}
		if got := s.dispatch(unknownRequest()); !bytes.HasSuffix(got, []byte("ERROR")) {
			t.Errorf("%s without success.raw: got %q, want error.raw", mode, got)
		}
	}
}

func TestSuccessModeSet(t *testing.T) {
	valid := map[string]successMode{
		"off": successOff, "false": successOff,
		"fallback": successFallback,
		"always":   successAlways, "true": successAlways,
		"ALWAYS": successAlways, " fallback ": successFallback,
	}
	for in, want := range valid {
		var m successMode
		if err := m.Set(in); err != nil || m != want {
			t.Errorf("Set(%q) = %v, err=%v; want %v", in, m, err, want)
		}
	}
	for _, in := range []string{"", "yes please", "success"} {
		var m successMode
		if err := m.Set(in); err == nil {
			t.Errorf("Set(%q) accepted, want an error", in)
		}
	}
}

func TestDNSRoundTrip(t *testing.T) {
	// Build a minimal query for gate1.us.dnas.playstation.org type A.
	q := buildQuery("gate1.us.dnas.playstation.org", 1)
	name, qtype, ok := parseQuestion(q)
	if !ok || qtype != 1 || name != "gate1.us.dnas.playstation.org" {
		t.Fatalf("parseQuestion got %q type=%d ok=%v", name, qtype, ok)
	}

	resp, err := buildAResponse(q, net.IPv4(192, 168, 1, 50))
	if err != nil {
		t.Fatal(err)
	}
	if resp[2]&0x80 == 0 {
		t.Fatal("QR bit not set in response")
	}
	if an := binary.BigEndian.Uint16(resp[6:8]); an != 1 {
		t.Fatalf("ANCOUNT = %d, want 1", an)
	}
	// Last 4 bytes are the A record IP.
	ip := net.IP(resp[len(resp)-4:])
	if !ip.Equal(net.IPv4(192, 168, 1, 50)) {
		t.Fatalf("answer IP = %s", ip)
	}
}

func TestDNSMatches(t *testing.T) {
	dnas := net.IPv4(10, 0, 0, 1)
	kddi := net.IPv4(10, 0, 0, 2)
	d := &DNSServer{Rules: []dnsRule{
		{suffix: "www01.kddi-mmbb.jp", ip: kddi},
		{suffix: "dnas.playstation.org", ip: dnas},
	}}
	sortRulesLongestFirst(d.Rules)

	cases := map[string]net.IP{
		"gate1.us.dnas.playstation.org":    dnas,
		"dnas.playstation.org":             dnas,
		"www01.kddi-mmbb.jp":               kddi,
		"example.com":                      nil,
		"notdnas.playstation.org.evil.com": nil,
	}
	for name, want := range cases {
		got := d.lookup(name)
		if (want == nil) != (got == nil) || (want != nil && !got.Equal(want)) {
			t.Errorf("lookup(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestLoadDNSConfig(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/dns.config"
	content := "# comment\ndnas.playstation.org\nwww01.kddi-mmbb.jp   192.168.2.30\n\n# blank line above\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	def := net.IPv4(10, 0, 0, 9)
	rules, err := loadDNSConfig(path, def)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	if rules[0].suffix != "dnas.playstation.org" || !rules[0].ip.Equal(def) {
		t.Errorf("rule 0 = %+v", rules[0])
	}
	if rules[1].suffix != "www01.kddi-mmbb.jp" || !rules[1].ip.Equal(net.IPv4(192, 168, 2, 30)) {
		t.Errorf("rule 1 = %+v", rules[1])
	}
}

// buildQuery constructs a minimal DNS query message for testing.
func buildQuery(name string, qtype uint16) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234) // ID
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT
	for _, label := range bytesSplit(name) {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0) // root
	var tc [4]byte
	binary.BigEndian.PutUint16(tc[0:2], qtype)
	binary.BigEndian.PutUint16(tc[2:4], 1) // IN
	return append(msg, tc[:]...)
}

func bytesSplit(name string) [][]byte {
	var out [][]byte
	cur := []byte{}
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			out = append(out, cur)
			cur = []byte{}
			continue
		}
		cur = append(cur, name[i])
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}
