package vantage

import (
	"os"
	"time"
)

// Timeout defaults.
//
// Two independent budgets are applied to every lookup:
//
//   - The *query* timeout bounds a single attempt against a single resolver.
//     Keeping it short means an unreachable nameserver is abandoned quickly and
//     the next one is tried, rather than stalling the whole audit.
//   - The *total* timeout bounds the lookup as a whole, across all resolvers.
//
// The defaults favour fast failover. Users auditing over slow, lossy or
// high-latency links (satellite, VPN, Tor, heavily filtered networks) can raise
// either budget via the CLI flags, the environment, or the library setters.
const (
	// DefaultQueryTimeout bounds a single attempt against a single resolver.
	DefaultQueryTimeout = 2 * time.Second
	// DefaultTotalTimeout bounds the entire lookup across all resolvers.
	DefaultTotalTimeout = 10 * time.Second
)

// DefaultTimeout is retained for backwards compatibility.
//
// Deprecated: use DefaultTotalTimeout (overall budget) or DefaultQueryTimeout
// (per-resolver budget) instead.
const DefaultTimeout = DefaultTotalTimeout

// Environment variables for tuning the timeouts without code or flags. Both
// accept any Go duration string, e.g. "500ms", "3s", "1m".
const (
	QueryTimeoutEnvVar = "VANTAGE_QUERY_TIMEOUT"
	TotalTimeoutEnvVar = "VANTAGE_TIMEOUT"
)

// ConfigFromEnv builds a Config from the environment, honouring
// VANTAGE_QUERY_TIMEOUT and VANTAGE_TIMEOUT. A caller layers its own flags on
// top of the result; precedence is therefore flag, then environment, then
// default, decided at the point a client is built rather than on every query.
func ConfigFromEnv() Config {
	var cfg Config
	if d, ok := durationFromEnv(QueryTimeoutEnvVar); ok {
		cfg.QueryTimeout = d
	}
	if d, ok := durationFromEnv(TotalTimeoutEnvVar); ok {
		cfg.TotalTimeout = d
	}
	return cfg
}

// durationFromEnv parses a positive duration from an environment variable.
func durationFromEnv(name string) (time.Duration, bool) {
	raw := os.Getenv(name)
	if raw == "" {
		return 0, false
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}
