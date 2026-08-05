package vantage

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// DefaultPort is the port assumed when a resolver address omits one.
const DefaultPort = "53"

// ResolverEnvVar is the name of the environment variable that can be used to
// override the resolvers used by vantage. It accepts a comma-separated list of
// addresses, with or without a port, e.g.:
//
//	VANTAGE_RESOLVERS="1.1.1.1,8.8.8.8:53,[2606:4700:4700::1111]:53"
const ResolverEnvVar = "VANTAGE_RESOLVERS"

// LegacyResolverEnvVar is the name this variable had before the rename from
// dnsaudit to vantage. It is still honoured, with lower precedence than
// ResolverEnvVar, because the failure mode otherwise is silent: a host that
// exported the old name would fall back to the system resolvers and keep
// producing results, just not the ones the operator configured. A changed
// resolver changes what the audit sees, so this must not go unnoticed.
const LegacyResolverEnvVar = "DNSAUDIT_RESOLVERS"

// FallbackResolvers are well-known public resolvers used as a last resort when
// the operating system's resolver configuration cannot be determined. This
// guarantees that vantage remains functional on any platform, including
// minimal containers and Windows hosts with unusual network configurations.
var FallbackResolvers = []string{
	"1.1.1.1:53",                // Cloudflare
	"8.8.8.8:53",                // Google
	"9.9.9.9:53",                // Quad9
	"[2606:4700:4700::1111]:53", // Cloudflare IPv6
}

// discoverResolvers performs the environment then platform then fallback lookup.
func discoverResolvers() []string {
	for _, name := range []string{ResolverEnvVar, LegacyResolverEnvVar} {
		env := strings.TrimSpace(os.Getenv(name))
		if env == "" {
			continue
		}
		if servers := normaliseServers(strings.Split(env, ",")); len(servers) > 0 {
			return servers
		}
	}
	if servers := normaliseServers(systemNameservers()); len(servers) > 0 {
		return servers
	}
	return append([]string(nil), FallbackResolvers...)
}

// normaliseServers cleans, de-duplicates and port-qualifies resolver addresses,
// discarding any entry that is not a usable address.
func normaliseServers(servers []string) []string {
	seen := make(map[string]struct{}, len(servers))
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		addr, err := normaliseServer(s)
		if err != nil {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

// normaliseServer returns the address in "host:port" form, appending the
// default DNS port when absent and bracketing bare IPv6 literals.
func normaliseServer(server string) (string, error) {
	s := strings.TrimSpace(server)
	if s == "" {
		return "", fmt.Errorf("error: empty resolver address")
	}

	// Already has a port (this also handles "[::1]:53").
	if host, port, err := net.SplitHostPort(s); err == nil && host != "" && port != "" {
		return net.JoinHostPort(host, port), nil
	}

	// Bare address; strip any IPv6 brackets and any zone-scoped suffix handling
	// is left to net.JoinHostPort.
	host := strings.Trim(s, "[]")
	if host == "" {
		return "", fmt.Errorf("error: invalid resolver address %q", server)
	}
	return net.JoinHostPort(host, DefaultPort), nil
}
