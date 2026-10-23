package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, raw string) httpRequest {
	t.Helper()
	ok, req := parseHTTPRequest([]byte(raw))
	if !ok {
		t.Fatalf("request not complete: %q", raw)
	}
	return req
}

func TestProxyForwardsRequest(t *testing.T) {
	var got *http.Request
	var gotBody []byte
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, gotBody = r, mustRead(t, r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Set-Cookie", "a=1")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "stored")
	}))
	defer backend.Close()

	rules, err := parseProxyRules([]string{"/amusa/=" + backend.URL + "/base/"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{DocRoot: t.TempDir(), Proxies: rules}
	req := mustParse(t, "POST /amusa/am_up.php?x=1 HTTP/1.0\r\nHost: rankweb.example\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\nContent-Length: 11\r\n\r\ncrs=A&utl=B")
	req.remote = "192.0.2.7"
	resp := string(s.dispatch(req))

	if got.Method != "POST" || got.URL.RequestURI() != "/base/amusa/am_up.php?x=1" || got.Host != "rankweb.example" {
		t.Errorf("backend saw %s %s Host %s", got.Method, got.URL.RequestURI(), got.Host)
	}
	if string(gotBody) != "crs=A&utl=B" || got.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("backend saw body %q, Content-Type %q", gotBody, got.Header.Get("Content-Type"))
	}
	if got.Header.Get("X-Forwarded-For") != "192.0.2.7" || got.Header.Get("X-Forwarded-Proto") != "https" {
		t.Errorf("backend saw X-Forwarded-For %q, X-Forwarded-Proto %q",
			got.Header.Get("X-Forwarded-For"), got.Header.Get("X-Forwarded-Proto"))
	}
	for _, want := range []string{"HTTP/1.0 201 Created\r\n", "Set-Cookie: a=1\r\n",
		"Content-Length: 6\r\nConnection: close\r\n\r\nstored"} {
		if !strings.Contains(resp, want) {
			t.Errorf("response %q lacks %q", resp, want)
		}
	}
}

func TestProxyLeavesOtherPathsAlone(t *testing.T) {
	rules, _ := parseProxyRules([]string{"/amusa/=http://127.0.0.1:1"})
	s := &Server{DocRoot: t.TempDir(), Proxies: rules}
	resp := string(s.dispatch(mustParse(t, "GET /amusa HTTP/1.0\r\n\r\n")))
	if !strings.HasPrefix(resp, "HTTP/1.0 404 Not Found\r\n") {
		t.Errorf("unmatched path got %q, want the static 404", resp)
	}
}

func TestProxyBackendDown(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	rules, _ := parseProxyRules([]string{"/x/=http://" + addr})
	s := &Server{Proxies: rules}
	resp := string(s.dispatch(mustParse(t, "GET /x/y HTTP/1.0\r\n\r\n")))
	if !strings.HasPrefix(resp, "HTTP/1.0 502 Bad Gateway\r\n") {
		t.Errorf("got %q, want 502", resp)
	}
}

func TestParseProxyRules(t *testing.T) {
	rules, err := parseProxyRules([]string{"/a/=http://h1", "/a/b/=https://h2:8443/p/"})
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].prefix != "/a/b/" || rules[0].target.String() != "https://h2:8443/p" || rules[1].prefix != "/a/" {
		t.Errorf("rules not longest-prefix first or target not normalised: %+v %+v", rules[0], rules[1])
	}
	for _, bad := range []string{"/a/", "a/=http://h", "/a/=ftp://h", "/a/=http://", "/a/=http://h/?q=1"} {
		if _, err := parseProxyRules([]string{bad}); err == nil {
			t.Errorf("parseProxyRules(%q) accepted", bad)
		}
	}
}

// A reply over 2^14 bytes, e.g. a proxied page, must span several records.
func TestLargeReplySplitIntoRecords(t *testing.T) {
	page := bytes.Repeat([]byte("x"), 40000)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(page) }))
	defer backend.Close()
	rules, _ := parseProxyRules([]string{"/p/=" + backend.URL})
	s := &Server{Proxies: rules}

	srvConn, cliConn := net.Pipe()
	defer cliConn.Close()
	go s.serveHTTP(&tls10Conn{conn: srvConn, br: bufio.NewReader(srvConn)})
	cliConn.SetDeadline(time.Now().Add(5 * time.Second))
	cli := &tls10Conn{conn: cliConn, br: bufio.NewReader(cliConn)}
	if err := cli.writeRecord(ctApplicationData, []byte("GET /p/ HTTP/1.0\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	var reply []byte
	for !bytes.HasSuffix(reply, page) {
		typ, frag, err := cli.readRecord()
		if err != nil {
			t.Fatalf("after %d bytes: %v", len(reply), err)
		}
		if typ != ctApplicationData || len(frag) > maxPlaintext {
			t.Fatalf("record type %d with %d bytes", typ, len(frag))
		}
		reply = append(reply, frag...)
	}
}

func mustRead(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
