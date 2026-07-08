package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// rulesFromSuffixes turns the built-in -dns-suffix list into redirect rules
// pointing at the default IP.
func rulesFromSuffixes(suffixes []string, defaultIP net.IP) []dnsRule {
	rules := make([]dnsRule, 0, len(suffixes))
	for _, s := range suffixes {
		if s = normalizeName(s); s != "" {
			rules = append(rules, dnsRule{suffix: s, ip: defaultIP})
		}
	}
	return rules
}

// loadDNSConfig parses a dns.config file. Each non-empty, non-comment line is:
//
//	<name> [ip]
//
// where <name> is a hostname or domain suffix to redirect and [ip] is an
// optional target IP (defaulting to defaultIP, i.e. -redirect-ip). Lines
// starting with '#' and blank lines are ignored.
//
//	# redirect the DNAS gateways to ourselves
//	dnas.playstation.org
//	# and a KDDI game server to a specific host
//	www01.kddi-mmbb.jp        192.168.2.30
func loadDNSConfig(path string, defaultIP net.IP) ([]dnsRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rules []dnsRule
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		name := normalizeName(fields[0])
		if name == "" {
			return nil, fmt.Errorf("%s:%d: empty hostname", path, line)
		}
		ip := defaultIP
		if len(fields) >= 2 {
			if ip = net.ParseIP(fields[1]); ip == nil {
				return nil, fmt.Errorf("%s:%d: invalid IP %q", path, line, fields[1])
			}
		}
		if ip == nil {
			return nil, fmt.Errorf("%s:%d: no target IP for %q and no -redirect-ip set", path, line, name)
		}
		rules = append(rules, dnsRule{suffix: name, ip: ip})
	}
	return rules, sc.Err()
}

func normalizeName(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// sortRulesLongestFirst orders rules so the most specific (longest) suffix wins
// when several rules could match the same name.
func sortRulesLongestFirst(rules []dnsRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		return len(rules[i].suffix) > len(rules[j].suffix)
	})
}

// dedupeRules keeps the first rule for each suffix and drops later duplicates.
// Callers put higher-precedence rules (e.g. dns.config) first.
func dedupeRules(in []dnsRule) []dnsRule {
	seen := make(map[string]bool, len(in))
	out := make([]dnsRule, 0, len(in))
	for _, r := range in {
		if seen[r.suffix] {
			continue
		}
		seen[r.suffix] = true
		out = append(out, r)
	}
	return out
}
