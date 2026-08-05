package vantage

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startMockDNSBoth starts a mock server listening on both UDP and TCP on the
// same port, so TCP fallback can be exercised.
func startMockDNSBoth(t *testing.T, mux *dns.ServeMux) (addr string, stop func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr = pc.LocalAddr().String()

	l, err := net.Listen("tcp", addr)
	require.NoError(t, err)

	udp := &dns.Server{PacketConn: pc, Net: "udp", Handler: mux}
	tcp := &dns.Server{Listener: l, Net: "tcp", Handler: mux}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()

	return addr, func() {
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
	}
}

// bigTXT builds a TXT record set whose wire form comfortably exceeds the 512
// byte limit that applies without EDNS0.
func bigTXT(name string) []dns.RR {
	var rrs []dns.RR
	for i := 0; i < 6; i++ {
		rrs = append(rrs, &dns.TXT{
			Hdr: dns.RR_Header{
				Name: name, Rrtype: dns.TypeTXT,
				Class: dns.ClassINET, Ttl: 300,
			},
			Txt: []string{strings.Repeat("x", 200)},
		})
	}
	return rrs
}

// TestExchangeHandlesOversizedUDPResponse is a regression test. Without an
// advertised EDNS0 buffer the response fails to unpack with "overflowing header
// size", which surfaced as an unreachable resolver and silently disabled checks
// on precisely the domains most worth auditing: those with large SPF trees.
func TestExchangeHandlesOversizedUDPResponse(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("big.example.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = bigTXT("big.example.")
		// Honour the client's advertised buffer, as a real resolver would.
		if opt := r.IsEdns0(); opt != nil {
			m.SetEdns0(opt.UDPSize(), false)
		}
		_ = w.WriteMsg(m)
	})

	addr, stop := startMockDNSBoth(t, mux)
	defer stop()

	msg, err := NewClient(Config{}).ExchangeWithServer(context.Background(), addr, "big.example", dns.TypeTXT)
	require.NoError(t, err, "an oversized response must not be reported as a failure")
	assert.Len(t, msg.Answer, 6, "the full record set must be returned")
}

// TestExchangeFallsBackToTCPWhenTruncated covers the other half of the same
// path: a server that truncates must be retried over TCP rather than yielding a
// partial answer, since a partial SPF record would produce false findings.
func TestExchangeFallsBackToTCPWhenTruncated(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("tc.example.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if _, isTCP := w.RemoteAddr().(*net.TCPAddr); isTCP {
			m.Answer = bigTXT("tc.example.")
			_ = w.WriteMsg(m)
			return
		}
		m.Truncated = true
		_ = w.WriteMsg(m)
	})

	addr, stop := startMockDNSBoth(t, mux)
	defer stop()

	msg, err := NewClient(Config{}).ExchangeWithServer(context.Background(), addr, "tc.example", dns.TypeTXT)
	require.NoError(t, err)
	assert.False(t, msg.Truncated, "the answer must come from the TCP retry")
	assert.Len(t, msg.Answer, 6)
}

// TestExchangeTreatsNXDOMAINAsNotFound is a regression test. NXDOMAIN is a
// definitive answer: the name does not exist. Reporting it as a generic error
// made callers record "check failed" for a question that had been answered,
// which in turn disabled DMARC organisational-domain fallback — the common
// case, since a subdomain with no policy of its own usually does not exist.
func TestExchangeTreatsNXDOMAINAsNotFound(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("gone.example.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		_ = w.WriteMsg(m)
	})

	addr, stop := startMockDNSBoth(t, mux)
	defer stop()

	client := NewClient(Config{Servers: []string{addr}})

	_, _, err := client.ExchangeFrom(context.Background(), "gone.example", dns.TypeTXT)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound,
		"NXDOMAIN must be distinguishable from a failure to determine an answer")
}

// TestExchangeReportsOtherFailureCodes keeps the distinction sharp: SERVFAIL
// means the resolver could not answer, which is genuinely a failed check and
// must not be reported as an absent record.
func TestExchangeReportsOtherFailureCodes(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("broken.example.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	})

	addr, stop := startMockDNSBoth(t, mux)
	defer stop()

	client := NewClient(Config{Servers: []string{addr}})

	_, _, err := client.ExchangeFrom(context.Background(), "broken.example", dns.TypeTXT)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotFound, "SERVFAIL is a failure, not an absence")
}
