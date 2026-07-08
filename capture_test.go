package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

// Real values captured from a PS2 DNAS handshake (JP gateway). This test proves
// that folding the raw SSLv2 hello body into the transcript reproduces the
// exact client Finished the console sent — the finding this whole TLS 1.0
// implementation rests on. It also shows that the canonical v3 reconstruction
// (what a transparent crypto/tls shim would hash) does NOT match.
const (
	capKeyPath  = "../DNASrep-master/etc/dnas/cert-jp-key.pem"
	capCertPath = "../DNASrep-master/etc/dnas/cert-jp.pem"

	capChallenge    = "54341c8daae99908b2480867f350554e"
	capServerRandom = "7e97811bb4f7bdf49f1a842d2732518f40ef9b1949c057e5444f574e47524400"
	capEncPremaster = "8028e127d9bd383f0d1091bae95e1c909ad88086adb4849b74e402587024" +
		"06f1ff7dde3ad6b9494b2dfd0ecedf39753017407ec9b59363c9bff2344016" +
		"50fd67db86d203ce3f69bb157eb0eeb7040b26524efbf89253c13662fa9b0e" +
		"e3ea76bce9e8091986bda5c4fb98605186048ad666a58c07c4df6827cafde226dcfeac25"
	capEncFinished = "8e59aa65c7514f32ff1b45c10ec6c1e2c70ddadf25e047f64577bf9e2eaf50632f51faa6a95dddf6"
	capVerifyData  = "8725f58ae4b8dfae36f0f7ef"
)

func mh(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCaptureTranscriptMatchesRealPS2(t *testing.T) {
	pemBytes, err := os.ReadFile(capKeyPath)
	if err != nil {
		t.Skipf("capture key not available (%v)", err)
	}
	blk, _ := pem.Decode(pemBytes)
	priv, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certPem, err := os.ReadFile(capCertPath)
	if err != nil {
		t.Skip("capture cert not available")
	}
	cblk, _ := pem.Decode(certPem)
	der := cblk.Bytes

	serverRandom := mh(t, capServerRandom)
	challenge := mh(t, capChallenge)
	clientRandom := append(make([]byte, 16), challenge...)
	encFinished := mh(t, capEncFinished)

	// premaster + master + client_write key material
	premaster, err := rsa.DecryptPKCS1v15(nil, priv, mh(t, capEncPremaster))
	if err != nil {
		t.Fatal(err)
	}
	master := prf10(premaster, []byte("master secret"),
		append(append([]byte{}, clientRandom...), serverRandom...), 48)
	kb := prf10(master, []byte("key expansion"),
		append(append([]byte{}, serverRandom...), clientRandom...), 2*macLen+2*keyLen+2*ivLen)
	cMAC := kb[0:macLen]
	cKey := kb[2*macLen : 2*macLen+keyLen]
	cIV := kb[2*macLen+2*keyLen : 2*macLen+2*keyLen+ivLen]

	// decrypt the client's Finished record and check its record MAC
	c := &tls10Conn{readActive: true, readCipher: must3DES(cKey), readIV: cIV, readMAC: cMAC}
	fin, err := c.decrypt(ctHandshake, encFinished)
	if err != nil {
		t.Fatalf("decrypting captured Finished (record MAC): %v", err)
	}
	if len(fin) != 16 || fin[0] != hsFinished {
		t.Fatalf("unexpected Finished layout: %x", fin)
	}
	actual := fin[4:16]
	if got := hex.EncodeToString(actual); got != capVerifyData {
		t.Fatalf("decrypted verify_data = %s, want %s", got, capVerifyData)
	}

	// Build the handshake messages after the ClientHello (all known/captured).
	serverHello := append([]byte{hsServerHello, 0, 0, 0x26, 0x03, 0x01}, serverRandom...)
	serverHello = append(serverHello, 0x00, 0x00, 0x0a, 0x00)
	certMsg := append([]byte{hsCertificate, 0x00, 0x02, byte(len(der) + 6), 0x00, byte((len(der) + 3) >> 8), byte(len(der) + 3), 0x00, byte(len(der) >> 8), byte(len(der))}, der...)
	shd := []byte{hsServerHelloDone, 0, 0, 0}
	cke := append([]byte{hsClientKeyExchange, 0, 0, 0x82, 0x00, 0x80}, mh(t, capEncPremaster)...)

	tail := func(clientHello []byte) []byte {
		var all []byte
		all = append(all, clientHello...)
		all = append(all, serverHello...)
		all = append(all, certMsg...)
		all = append(all, shd...)
		all = append(all, cke...)
		return prf10(master, []byte("client finished"), finishedHash(all), 12)
	}

	// v2 body (100 bytes) — what the PS2 actually hashes
	v2body := buildV2Hello(challenge)[2:]
	if !bytes.Equal(tail(v2body), actual) {
		t.Fatalf("v2-body transcript did NOT reproduce the PS2 verify_data")
	}

	// canonical v3 reconstruction — must NOT match (this is why a shim fails)
	v3 := canonicalV3(clientRandom)
	if bytes.Equal(tail(v3), actual) {
		t.Fatal("canonical v3 unexpectedly matched; shim assumption would have held")
	}
}

// canonicalV3 builds the v3 ClientHello a transparent shim would have produced.
func canonicalV3(clientRandom []byte) []byte {
	suites := []byte{
		0x00, 0x66, 0x00, 0x16, 0x00, 0x13, 0x00, 0x0a, 0x00, 0x05, 0x00, 0x04,
		0x00, 0x15, 0x00, 0x12, 0x00, 0x09, 0x00, 0x63, 0x00, 0x65, 0x00, 0x62,
		0x00, 0x64, 0x00, 0x14, 0x00, 0x11, 0x00, 0x08, 0x00, 0x06, 0x00, 0x03,
	}
	b := []byte{0x03, 0x01}
	b = append(b, clientRandom...)
	b = append(b, 0x00)
	b = append(b, byte(len(suites)>>8), byte(len(suites)))
	b = append(b, suites...)
	b = append(b, 0x01, 0x00)
	return append([]byte{hsClientHello, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b...)
}
