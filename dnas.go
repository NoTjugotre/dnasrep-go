package main

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// encrypt3n reproduces the encrypt3n() routine from connect.php.
//
// It is a 3DES-EDE in CBC mode over data[offset:offset+length]:
//   - the three DES keys form the EDE triple (encrypt-k1, decrypt-k2, encrypt-k3)
//   - xorSeed is the CBC IV; each ciphertext block chains into the next
//
// length must be a multiple of the DES block size (8). The slice is modified
// in place and also returned for convenience.
func encrypt3n(data []byte, offset, length int, k1, k2, k3, xorSeed []byte) ([]byte, error) {
	if offset+length > len(data) {
		return nil, errors.New("encrypt3n: region exceeds buffer")
	}
	if length%des.BlockSize != 0 {
		return nil, errors.New("encrypt3n: length not a multiple of 8")
	}
	// 3DES wants a 24-byte key: k1 || k2 || k3.
	key := make([]byte, 0, 24)
	key = append(key, k1...)
	key = append(key, k2...)
	key = append(key, k3...)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCEncrypter(block, xorSeed)
	cbc.CryptBlocks(data[offset:offset+length], data[offset:offset+length])
	return data, nil
}

// deriveKeys reproduces "step 0" of connect.php: it builds the four 8-byte DES
// keys/seed from SHA1 checksums over two regions of the request packet.
func deriveKeys(req []byte) (k1, k2, k3, seed []byte, err error) {
	if len(req) < 0x48+0xec {
		return nil, nil, nil, nil, errors.New("request too short for key derivation")
	}
	sum1 := sha1.Sum(req[0x34 : 0x34+0x100])
	sum2 := sha1.Sum(req[0x48 : 0x48+0xec])
	chksum1 := hex.EncodeToString(sum1[:]) // 40 hex chars
	chksum2 := hex.EncodeToString(sum2[:]) // 40 hex chars

	// fullkey = chksum2[0:40] + chksum1[0:24]  => 64 hex chars = 32 bytes
	fullkey := chksum2[:0x14*2] + chksum1[:0x0c*2]

	dec := func(a, b int) ([]byte, error) { return hex.DecodeString(fullkey[a:b]) }
	if k1, err = dec(0x00, 0x10); err != nil {
		return
	}
	if k2, err = dec(0x10, 0x20); err != nil {
		return
	}
	if k3, err = dec(0x20, 0x30); err != nil {
		return
	}
	if seed, err = dec(0x30, 0x40); err != nil {
		return
	}
	return
}

// Fixed "envelope" keyset, identical for every region (see connect.php step 3).
var (
	envK1   = mustHex("eb711416cb0ab016")
	envK2   = mustHex("ae190174b5ce6339")
	envK3   = mustHex("7b01b91880145e34")
	envSeed = mustHex("c510a6400a9b022f")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// packetName builds the "<gameID>_<qrytype>" filename used to look up a
// captured reply. gameIDOff differs between the connect (0x2c) and the
// others (0x1b) query layouts.
func packetName(req []byte, gameIDOff int) (string, bool) {
	if len(req) < gameIDOff+8 || len(req) < 4 {
		return "", false
	}
	gameID := req[gameIDOff : gameIDOff+8]
	qrytype := req[0:4]
	return hex.EncodeToString(gameID) + "_" + hex.EncodeToString(qrytype), true
}

// loadPacket reads a captured reply from <gwDir>/packets/<name>, guarding
// against path traversal (name is hex-only, but we stay defensive).
func loadPacket(gwDir, name string) ([]byte, error) {
	if strings.ContainsAny(name, "/\\") {
		return nil, os.ErrNotExist
	}
	return os.ReadFile(filepath.Join(gwDir, "packets", name))
}

// connectReply reproduces connect.php (the "v2.5_i-connect" endpoint) and
// returns the raw reply payload.
func (s *Server) connectReply(gwDir string, req []byte) []byte {
	name, ok := packetName(req, 0x2c)
	if !ok {
		return s.errorRaw(gwDir)
	}
	packet, err := loadPacket(gwDir, name)
	if err != nil {
		return s.missingPacketReply(gwDir, name)
	}
	k1, k2, k3, seed, err := deriveKeys(req)
	if err != nil {
		return s.errorRaw(gwDir)
	}
	// step 2 - encrypt with keyset derived from the query packet
	if _, err = encrypt3n(packet, 0xc8, 0x20, k1, k2, k3, seed); err != nil {
		return s.errorRaw(gwDir)
	}
	// step 3 - encrypt with the fixed envelope keyset
	if _, err = encrypt3n(packet, 0x28, 0x120, envK1, envK2, envK3, envSeed); err != nil {
		return s.errorRaw(gwDir)
	}
	return packet
}

// othersReply reproduces others.php (the "v2.5_others" endpoint): a plain
// replay of the captured reply, no encryption.
func (s *Server) othersReply(gwDir string, req []byte) []byte {
	name, ok := packetName(req, 0x1b)
	if !ok {
		return s.errorRaw(gwDir)
	}
	packet, err := loadPacket(gwDir, name)
	if err != nil {
		return s.missingPacketReply(gwDir, name)
	}
	return packet
}

// missingPacketReply answers a request that has no captured reply in packets/.
// Normally that is the gateway's error.raw; with -force-success=fallback the
// success.raw is sent instead, which is the point of the workaround. Requests
// that are malformed (rather than merely uncaptured) still get error.raw.
func (s *Server) missingPacketReply(gwDir, name string) []byte {
	if s.ForceSuccess == successFallback {
		log.Printf("https: force-success: no capture %q - answering with success.raw", name)
		return s.successRaw(gwDir)
	}
	return s.errorRaw(gwDir)
}

// successRaw returns the gateway's success.raw payload, the counterpart to
// error.raw. It is only reached via the -force-success workaround (see
// Server.ForceSuccess); a gateway without a success.raw falls back to the
// error reply so the client still gets a well-formed answer.
func (s *Server) successRaw(gwDir string) []byte {
	b, err := os.ReadFile(filepath.Join(gwDir, "success.raw"))
	if err != nil {
		log.Printf("https: force-success: %v - falling back to error.raw", err)
		return s.errorRaw(gwDir)
	}
	return b
}

// errorRaw returns the gateway's error.raw payload (the "auth failed" reply).
func (s *Server) errorRaw(gwDir string) []byte {
	b, err := os.ReadFile(filepath.Join(gwDir, "error.raw"))
	if err != nil {
		return nil
	}
	return b
}

// gwDirFor maps a request path like "/us-gw/v2.5_i-connect" to the on-disk
// gateway directory "<docroot>/us-gw", staying inside the document root.
func (s *Server) gwDirFor(urlPath string) (string, bool) {
	clean := path.Clean("/" + urlPath)
	dir := path.Dir(clean) // e.g. "/us-gw"
	full := filepath.Join(s.DocRoot, filepath.FromSlash(dir))
	rel, err := filepath.Rel(s.DocRoot, full)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", false
	}
	return full, true
}
