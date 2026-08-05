package vantage

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// Resolver is the DNS egress boundary.
//
// Every query vantage makes passes through this interface, which is what
// allows an embedding consumer to supply its own implementation and enforce a
// policy at the point of egress rather than merely declining to call. A
// consumer that refuses a name here makes it unreachable, not just unrequested
// — a materially stronger guarantee, and the reason this interface exists at
// all rather than a configuration struct.
//
// Implementations must be safe for concurrent use.
type Resolver interface {
	// ExchangeFrom queries the configured resolvers in turn and reports which
	// one answered. A non-success response code is an error, except NXDOMAIN,
	// which is returned as ErrNotFound because it is a definitive answer
	// rather than a failure to obtain one.
	ExchangeFrom(ctx context.Context, name string, qtype uint16) (*dns.Msg, string, error)

	// ExchangeRawFrom behaves like ExchangeFrom but leaves the response code
	// for the caller to interpret.
	ExchangeRawFrom(ctx context.Context, name string, qtype uint16) (*dns.Msg, string, error)

	// ExchangeDNSSECRawFrom requests DNSSEC records (the EDNS0 DO bit) and
	// leaves the response code uninterpreted, which is required when querying
	// a deliberately absent name to obtain denial-of-existence records.
	ExchangeDNSSECRawFrom(ctx context.Context, name string, qtype uint16) (*dns.Msg, string, error)

	// ExchangeWithServer queries one explicit server, bypassing the configured
	// resolvers. Checks that must speak to the target's own authoritative
	// nameservers use it, and it is therefore the method a scope-enforcing
	// implementation must guard most carefully: the server address is chosen
	// by the check, not by configuration.
	ExchangeWithServer(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error)

	// ExchangeDNSSECWithServer is ExchangeWithServer with DNSSEC records
	// requested.
	ExchangeDNSSECWithServer(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error)

	// Servers reports the resolver addresses in use, for evidence. A finding
	// that names the resolver which answered is reproducible by a reader whose
	// own resolver may see something different, whether through split-horizon
	// DNS, filtering or an outright hijack.
	Servers() []string
}

// Config configures a Client. The zero value is usable: resolvers are
// discovered from the platform and the default timeouts apply.
//
// Configuration is per-client rather than process-global precisely so that two
// assessments running concurrently under different scopes cannot disturb each
// other — which package-level setters made impossible to guarantee.
type Config struct {
	// Servers are the resolver addresses to query, in order. Addresses may be
	// given with or without a port; 53 is assumed. Empty means discover them
	// from the platform.
	Servers []string

	// QueryTimeout bounds a single attempt against a single resolver. A short
	// value abandons a dead nameserver quickly rather than stalling the run.
	// Non-positive means DefaultQueryTimeout.
	QueryTimeout time.Duration

	// TotalTimeout bounds the whole lookup across all resolvers. Non-positive
	// means DefaultTotalTimeout.
	TotalTimeout time.Duration
}

// Client is the default Resolver: it queries real nameservers over the network.
//
// It is immutable once built. Reconfiguring means constructing another client,
// which is what makes concurrent use safe without locking and removes any
// possibility of one assessment's settings leaking into another's.
type Client struct {
	servers      []string
	queryTimeout time.Duration
	totalTimeout time.Duration
}

// Compile-time assertion that Client satisfies the interface it defines.
var _ Resolver = (*Client)(nil)

// NewClient builds a Client from a Config, resolving every default eagerly so
// that the client's behaviour cannot change underneath a run in progress.
//
// Resolver discovery happens here, once, rather than on each query: a
// long-running process whose network configuration changes gets a new client,
// so the change is an explicit act rather than a silent shift in what the
// audit was measured against.
func NewClient(cfg Config) *Client {
	servers := normaliseServers(cfg.Servers)
	if len(servers) == 0 {
		servers = discoverResolvers()
	}

	query := cfg.QueryTimeout
	if query <= 0 {
		query = DefaultQueryTimeout
	}
	total := cfg.TotalTimeout
	if total <= 0 {
		total = DefaultTotalTimeout
	}

	return &Client{servers: servers, queryTimeout: query, totalTimeout: total}
}

// Servers implements Resolver.
func (c *Client) Servers() []string {
	return append([]string(nil), c.servers...)
}

// QueryTimeout reports the per-resolver attempt budget.
func (c *Client) QueryTimeout() time.Duration { return c.queryTimeout }

// TotalTimeout reports the overall lookup budget.
func (c *Client) TotalTimeout() time.Duration { return c.totalTimeout }

// budget returns the time available for a lookup, honouring the caller's
// context deadline when it is sooner than the client's total budget.
func (c *Client) budget(ctx context.Context) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	remaining := c.totalTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if until := time.Until(deadline); until < remaining {
			remaining = until
		}
	}
	if remaining <= 0 {
		return 0, context.DeadlineExceeded
	}
	return remaining, nil
}

// attemptTimeout bounds one attempt: the per-query budget, or whatever remains
// of the total budget if that is less.
func (c *Client) attemptTimeout(remaining time.Duration) time.Duration {
	if c.queryTimeout < remaining {
		return c.queryTimeout
	}
	return remaining
}

// ExchangeWithServer implements Resolver.
//
// Because there is no other resolver to fail over to, the attempt is given the
// full lookup budget rather than the shorter per-resolver one.
func (c *Client) ExchangeWithServer(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error) {
	return c.exchangeWithServer(ctx, server, name, qtype, false)
}

// ExchangeDNSSECWithServer implements Resolver.
func (c *Client) ExchangeDNSSECWithServer(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error) {
	return c.exchangeWithServer(ctx, server, name, qtype, true)
}

func (c *Client) exchangeWithServer(ctx context.Context, server, name string, qtype uint16, dnssec bool) (*dns.Msg, error) {
	addr, err := normaliseServer(server)
	if err != nil {
		return nil, err
	}
	remaining, err := c.budget(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := exchangeOnce(ctx, addr, question(name, qtype), remaining, dnssec)
	if err != nil {
		return nil, fmt.Errorf("error: dns query failed: %w: %w", ErrResolverUnreachable, err)
	}
	return resp, nil
}

// ExchangeRawFrom implements Resolver.
func (c *Client) ExchangeRawFrom(ctx context.Context, name string, qtype uint16) (*dns.Msg, string, error) {
	return c.exchangeRawFrom(ctx, name, qtype, false)
}

// ExchangeDNSSECRawFrom implements Resolver.
func (c *Client) ExchangeDNSSECRawFrom(ctx context.Context, name string, qtype uint16) (*dns.Msg, string, error) {
	return c.exchangeRawFrom(ctx, name, qtype, true)
}

func (c *Client) exchangeRawFrom(ctx context.Context, name string, qtype uint16, dnssec bool) (*dns.Msg, string, error) {
	remaining, err := c.budget(ctx)
	if err != nil {
		return nil, "", err
	}
	deadline := time.Now().Add(remaining)

	if len(c.servers) == 0 {
		return nil, "", fmt.Errorf("error: no DNS resolvers available: %w", ErrResolverUnreachable)
	}

	m := question(name, qtype)
	var lastErr error
	for _, server := range c.servers {
		remaining = time.Until(deadline)
		if remaining <= 0 {
			if lastErr == nil {
				lastErr = context.DeadlineExceeded
			}
			break
		}
		resp, err := exchangeOnce(ctx, server, m, c.attemptTimeout(remaining), dnssec)
		if err == nil {
			return resp, server, nil
		}
		lastErr = err
		// Stop early if the caller cancelled or their deadline expired.
		if ctx.Err() != nil {
			break
		}
	}
	return nil, "", fmt.Errorf("error: dns query failed: %w: %w", ErrResolverUnreachable, lastErr)
}

// ExchangeFrom implements Resolver.
func (c *Client) ExchangeFrom(ctx context.Context, name string, qtype uint16) (*dns.Msg, string, error) {
	resp, server, err := c.ExchangeRawFrom(ctx, name, qtype)
	if err != nil {
		return nil, "", err
	}
	if resp.Rcode == dns.RcodeNameError {
		// NXDOMAIN is a definitive answer — the name does not exist — not a
		// failure to obtain one. Returning a generic error here would make
		// callers report "check failed" for a question that was answered
		// conclusively, hiding absent records behind an apparent fault.
		return nil, server, ErrNotFound
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, server, fmt.Errorf("error: dns response code %d", resp.Rcode)
	}
	return resp, server, nil
}

// LookupTXTFrom retrieves TXT records and reports which resolver answered.
func LookupTXTFrom(ctx context.Context, r Resolver, domain string) ([]string, string, error) {
	resp, server, err := r.ExchangeFrom(ctx, domain, dns.TypeTXT)
	if err != nil {
		return nil, server, err
	}
	var txts []string
	for _, rr := range resp.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			txts = append(txts, joinTXTStrings(t.Txt))
		}
	}
	if len(txts) == 0 {
		return nil, server, ErrNotFound
	}
	return txts, server, nil
}

// LookupTXT retrieves TXT records for the given domain.
func LookupTXT(ctx context.Context, r Resolver, domain string) ([]string, error) {
	txts, _, err := LookupTXTFrom(ctx, r, domain)
	return txts, err
}

// joinTXTStrings concatenates the character-strings of a TXT record back into
// the value the operator published.
//
// A TXT record longer than 255 bytes travels as several strings. Treating them
// as separate records splits a 2048-bit DKIM key into unparseable fragments,
// and makes one long SPF record look like the duplicate that RFC 7208 treats
// as a PermError — inventing findings out of a wire-format detail.
func joinTXTStrings(parts []string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return string(b)
}
