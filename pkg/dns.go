package vantage

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"
)

// ErrNotFound is returned when a query succeeds but yields no usable record.
var ErrNotFound = errors.New("error: not found")

// question builds a recursive query message for the given name and type.
func question(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	return m
}

// udpBufferSize is the EDNS0 receive buffer advertised on UDP queries. 1232
// bytes is the widely-adopted DNS Flag Day figure: large enough for the
// records this tool retrieves, small enough to stay clear of IP fragmentation,
// which is both unreliable in practice and a spoofing aid.
const udpBufferSize = 1232

// exchangeOnce sends the query to a single resolver, retrying over TCP when the
// UDP response is truncated. The attempt is bounded both by the supplied
// timeout and by the caller's context.
//
// When dnssec is set the EDNS0 DO bit is requested, so that the resolver
// returns RRSIG records and sets the AD bit on validated answers. Without it a
// DNSSEC query sees only the records the zone publishes, never the signatures
// that determine whether they can actually be validated.
func exchangeOnce(ctx context.Context, addr string, m *dns.Msg, timeout time.Duration, dnssec bool) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Pace queries per resolver so that a concurrent audit never resembles an
	// attack, and never trips rate limiting that would turn into spurious
	// findings.
	if err := awaitQuerySlot(ctx, addr); err != nil {
		return nil, err
	}

	client := &dns.Client{Timeout: timeout, UDPSize: udpBufferSize}

	// Advertise a larger receive buffer. Without EDNS0 the limit is 512 bytes,
	// which large TXT responses routinely exceed — and a domain with a big SPF
	// include tree is exactly the case worth auditing. The query is sent on a
	// copy so that a retry over TCP re-sends the caller's original message.
	edns := m.Copy()
	edns.SetEdns0(udpBufferSize, dnssec)

	resp, _, err := client.ExchangeContext(ctx, edns, addr)

	// Fall back to TCP not only when the server sets the truncation flag, but
	// also when the response could not be parsed. An oversized answer can fail
	// to unpack before the flag is ever read, and reporting that as an
	// unreachable resolver would hide a perfectly healthy domain behind a
	// transport detail.
	//
	// DNSKEY and RRSIG answers routinely exceed the UDP buffer, so the retry
	// must carry the same EDNS0 options: re-sending the bare question would
	// drop the DO bit and silently return an unsigned view of a signed zone.
	if err != nil || resp.Truncated {
		retry := m
		if dnssec {
			retry = edns
		}
		tcp := &dns.Client{Net: "tcp", Timeout: timeout}
		if tcpResp, _, tcpErr := tcp.ExchangeContext(ctx, retry, addr); tcpErr == nil {
			return tcpResp, nil
		}
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}
