package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// A real install authentication and its replies, decrypted: its install
// queries (0110) have no capture of their own and must be answered with the
// normal replies (0118) marked as install replies, byte for byte.
const (
	installConnectRequest = "" +
		"0110000000000000000000000000000000000000000000000000000000000000000000000000010c000200050d775aac" +
		"7583e2f7b3523fea382c5681dad7b922ff0749c69cce5ac58b09ee30c1c578d9b452c43ba89f392e941c1acf654c4c1f" +
		"d19534ecd2b6088c42f6f4c8ca25181338c435d4d9a61fe8cb30e3b1bc6377ae12a914045337bb3bf0c917ae76318129" +
		"35a6899c4a2b9ecddb8838cdb98a7820156dede2a6ef83d3622c511d84736327c6b0ab452c625b9e762d6b01a310cc9b" +
		"72d307e6535c19f05f82adf509507d2f59f5eb5cd5df857b906ffec64c363f332bf51e6489383323d0b2b3d390e0f866" +
		"0a7dfb2995d9851a0aeb68855d7f3980bb1b963d069413ac885efc40a1a44d9ec6a039b69c98e507ab3a597085ed06aa" +
		"731791f80e080a4b54d6cf769978b9d8bfa89a17"
	installConnectReply = "" +
		"011000050206085c36380b120907e0000069ee0000000000000000c70d68bc431b1d4ec500000120dccc2f9c310536a6" +
		"cff3341c153d0eddc22c09ce774d3daa31dfc0f7d136c27937f1d0829485eec14fa5c89efe30831f504adae943aaee40" +
		"2fcca509ef89ef97e6c1f47d9fbb6062fa0dc1a879571307b84a195337504c8c14ef741d2c786bc2abee40de0c7b4dd2" +
		"c5bf1abc820f92119eac97a3525ac3c902a997e9bdc76f7ec45b4124d2a8dcd91edfd694c9fb7b3b9595217fa7f766de" +
		"6bd310e166c66aa4ceb0a5088c66b7ff12c71db54ef0dba4418e3e66601da5e6615c9025413b0d772ab2809d54cc7508" +
		"b0b39778f315d1e223866766002b789b3620e561b30d9d0ceed8f0836a0249d349e7fdfa4e40c21ed840e9aeebd1d02f" +
		"1cc8cc76ee2d9c6935d25cecbd05f634717a45ceea6533e56757752a31d70fd30bd7ac724d82de1a"
	installOthersRequest = "" +
		"011080010206085c36380b120907e0000069ee0000000000000000c70d68bc431b1d4ec500000090b20c01e90fa85d4d" +
		"01075ff44652ce6e9d047929581cce82fdbee135aa3cb6933dc3468b21ef9a154ea117bc706a030d6e7d37c69a064897" +
		"c429cc6f668303a347492f6838c97e866b9543dbff46e96ec321345d287df5eca7c15c0d455fb18ca8e0f5e0aa736716" +
		"08aaf108f0db76b4fdab1225280712d0c96edd0fcd8f9b766f90571a030000000000000000000000"
	installOthersReply = "" +
		"011080060206085c36380b120907e0000069ee0000000000000000c70d68bc431b1d4ec500000082020148ee19adaf1f" +
		"05e45cc37d5fd2529017be1565ad8fe8ab083d1e5aae9631c449e3510705e48fef10df10b1aa09589ef68896f2bfdcaf" +
		"ddbbbdf8b65a60bcc80945a48b4576cf53d4f77082e9702d38d2e3839da1d0fdab78a2a444a7d020d25d50031edb9e3f" +
		"ba0b2c7f1ac45d65e2504d45ff8a4f1b39ef01dbeb5216bb515d"
)

func TestInstallQueryAnsweredFromNormalCapture(t *testing.T) {
	s := &Server{DocRoot: "gate"}
	cases := []struct {
		name           string
		serve          func(string, []byte) []byte
		request, reply string
	}{
		{"connect", s.connectReply, installConnectRequest, installConnectReply},
		{"others", s.othersReply, installOthersRequest, installOthersReply},
	}
	for _, tc := range cases {
		request, _ := hex.DecodeString(tc.request)
		want, _ := hex.DecodeString(tc.reply)
		if got := tc.serve("gate/us-gw", request); !bytes.Equal(got, want) {
			t.Errorf("%s: install reply differs from the captured one", tc.name)
		}
	}
}

func TestNormalQueryWithoutCaptureStaysAnError(t *testing.T) {
	s := &Server{DocRoot: "gate"}
	request, _ := hex.DecodeString(installConnectRequest)
	request[1] = 0x18
	request[0x2c] ^= 0xff // a title with no capture at all
	if got, want := s.connectReply("gate/us-gw", request), s.errorRaw("gate/us-gw"); !bytes.Equal(got, want) {
		t.Errorf("uncaptured title got %d bytes, want error.raw", len(got))
	}
}

func TestInstallQueryGetsInstallSuccessReply(t *testing.T) {
	gw := t.TempDir()
	success := []byte{0x01, 0x18, 0x00, 0x04, 0, 0, 0, 0}
	if err := os.WriteFile(filepath.Join(gw, "success.raw"), success, 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Server{ForceSuccess: successFallback}
	// success.raw is relabelled with the request's op byte for every operation,
	// including the PS2BBN Navigator's 0x22 (PlayStation BB Navigator 0.30,
	// SCPN-60140) that the DNASrep notes describe as "edit success.raw to 01 22".
	for _, op := range []byte{0x10, 0x18, 0x08, 0x22} {
		request := make([]byte, 308)
		request[0], request[1] = 0x01, op
		got := s.connectReply(gw, request)
		if len(got) != len(success) || got[0] != 0x01 || got[1] != op {
			t.Errorf("query op %#x: success reply % x, want it to start 01 %02x", op, got, op)
		}
	}
}

func TestInstallQueryFallsBackToUniqueIDCapture(t *testing.T) {
	gw := t.TempDir()
	if err := os.Mkdir(filepath.Join(gw, "packets"), 0o755); err != nil {
		t.Fatal(err)
	}
	request, _ := hex.DecodeString(installOthersRequest)
	uniqueID := append([]byte(nil), request...)
	uniqueID[1] = 0x08
	name, _ := packetName(uniqueID, 0x1b)
	captured := []byte{0x01, 0x08, 0x80, 0x06, 0xaa, 0xbb}
	if err := os.WriteFile(filepath.Join(gw, "packets", name), captured, 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	want := []byte{0x01, 0x10, 0x80, 0x06, 0xaa, 0xbb}
	if got := s.othersReply(gw, request); !bytes.Equal(got, want) {
		t.Errorf("install reply % x, want % x", got, want)
	}
}
