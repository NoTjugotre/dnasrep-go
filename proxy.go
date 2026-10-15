package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// proxyRule forwards requests whose path starts with prefix to an HTTP
// backend. Games that use the console's SSL library for more than DNAS (e.g.
// ranking uploads) reach this server too, since only it can complete their
// handshake; -proxy hands those requests to the server that actually serves
// them.
type proxyRule struct {
	prefix string
	target *url.URL
}

// maxProxyBody caps the backend response read into memory.
const maxProxyBody = 8 << 20

// hopByHop lists the headers that describe one connection, not the request,
// and are therefore never forwarded (RFC 7230 6.1). Content-Length is rebuilt.
var hopByHop = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Proxy-Connection": true, "Te": true,
	"Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
	"Content-Length": true,
}

var proxyClient = &http.Client{
	Timeout: 30 * time.Second,
	// Hand redirects back to the console rather than following them here.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	// Pass bodies through byte for byte.
	// Ignore HTTP_PROXY: the backend is named explicitly.
	Transport: &http.Transport{Proxy: nil, DisableCompression: true},
}

// parseProxyRules parses -proxy values of the form PREFIX=URL, e.g.
// "/amusa/=http://127.0.0.1:8080". Longer prefixes are matched first.
func parseProxyRules(values []string) ([]proxyRule, error) {
	rules := make([]proxyRule, 0, len(values))
	for _, v := range values {
		prefix, raw, ok := strings.Cut(v, "=")
		if !ok || !strings.HasPrefix(prefix, "/") {
			return nil, fmt.Errorf("invalid -proxy %q (want /prefix=http://host[:port][/path])", v)
		}
		target, err := url.Parse(raw)
		if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" ||
			target.RawQuery != "" || target.Fragment != "" {
			return nil, fmt.Errorf("invalid -proxy target %q (want http://host[:port][/path])", raw)
		}
		target.Path = strings.TrimSuffix(target.Path, "/")
		rules = append(rules, proxyRule{prefix: prefix, target: target})
	}
	sort.SliceStable(rules, func(i, j int) bool { return len(rules[i].prefix) > len(rules[j].prefix) })
	return rules, nil
}

// proxyFor returns the rule matching the request path, or nil.
func (s *Server) proxyFor(urlPath string) *proxyRule {
	for i := range s.Proxies {
		if strings.HasPrefix(urlPath, s.Proxies[i].prefix) {
			return &s.Proxies[i]
		}
	}
	return nil
}

// proxy forwards one request to the rule's backend and returns its response
// as an HTTP/1.0 reply, the form every other reply of this server takes. The
// full request path (with its query) is appended to the target URL's path.
func (s *Server) proxy(rule *proxyRule, req httpRequest) []byte {
	target := rule.target.Scheme + "://" + rule.target.Host + rule.target.Path + req.path
	out, err := http.NewRequest(req.method, target, bytes.NewReader(req.body))
	if err != nil {
		log.Printf("https: proxy %s %s: %v", req.method, req.path, err)
		return httpStatus("400 Bad Request")
	}
	for k, vs := range req.header {
		if !hopByHop[k] {
			out.Header[k] = vs
		}
	}
	out.Host = req.header.Get("Host")
	if req.remote != "" {
		out.Header.Add("X-Forwarded-For", req.remote)
	}
	out.Header.Set("X-Forwarded-Proto", "https")

	resp, err := proxyClient.Do(out)
	if err != nil {
		log.Printf("https: proxy %s %s -> %s: %v", req.method, req.path, target, err)
		return httpStatus("502 Bad Gateway")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyBody+1))
	if err != nil || len(body) > maxProxyBody {
		log.Printf("https: proxy %s %s -> %s: response body unreadable or over %d bytes", req.method, req.path, target, maxProxyBody)
		return httpStatus("502 Bad Gateway")
	}
	log.Printf("https: proxy %s %s -> %s: %s (%d-byte body)", req.method, req.path, target, resp.Status, len(body))

	var head strings.Builder
	fmt.Fprintf(&head, "HTTP/1.0 %s\r\n", resp.Status)
	for k, vs := range resp.Header {
		if hopByHop[k] {
			continue
		}
		for _, v := range vs {
			fmt.Fprintf(&head, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&head, "Content-Length: %d\r\nConnection: close\r\n\r\n", len(body))
	return append([]byte(head.String()), body...)
}
