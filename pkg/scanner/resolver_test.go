package scanner_test

// resolver_test.go exercises the scanner's public (non-"WithServer") API by
// pointing the platform-independent resolver machinery at a local mock DNS
// server. This proves the same code path works regardless of how — or whether —
// the host operating system exposes a resolver configuration, which is what
// makes the tool usable on Linux, macOS and Windows alike.

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vantage "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/scanner"
)

// useMockResolver returns a client pointed at the given address.
//
// It returns the client rather than installing it anywhere: with the resolver
// injected there is no ambient configuration to restore, so the helper needs
// no cleanup and tests using it can run in parallel.
func useMockResolver(t *testing.T, addr string) vantage.Resolver {
	t.Helper()
	return vantage.NewClient(vantage.Config{Servers: []string{addr}})
}

func TestPublicAPIUsesConfiguredResolver(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("resolver.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: "resolver.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
			Txt: []string{"v=spf1 include:_spf.example.com -all"},
		})
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()
	testResolver := useMockResolver(t, addr)

	spf, err := scanner.LookupSPF(context.Background(), testResolver, "resolver.test")
	require.NoError(t, err)
	assert.Equal(t, "v=spf1 include:_spf.example.com -all", spf)
}

func TestCheckDNSSEC_Enabled(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("dnssec.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: "dnssec.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
			Flags:     257,
			Protocol:  3,
			Algorithm: 8,
			PublicKey: "AwEAAb==",
		})
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	status, err := scanner.CheckDNSSECWithServer(context.Background(), testResolver, "dnssec.test", addr)
	require.NoError(t, err)
	assert.Equal(t, "enabled", status)
}

func TestCheckDNSSEC_NotFoundIsAValueNotAnError(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("nodnskey.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	status, err := scanner.CheckDNSSECWithServer(context.Background(), testResolver, "nodnskey.test", addr)
	require.NoError(t, err)
	assert.Equal(t, "not found", status)
}

func TestLookupDKIM_Found(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("sel1._domainkey.dkim.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: "sel1._domainkey.dkim.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
			Txt: []string{"v=DKIM1; k=rsa; p=MIGfMA0G"},
		})
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	rec, err := scanner.LookupDKIMWithServer(context.Background(), testResolver, "dkim.test", "sel1", addr)
	require.NoError(t, err)
	assert.Contains(t, rec, "v=DKIM1")
}

func TestReverseLookupPTR_UsesConfiguredResolver(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("ptr.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: "ptr.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("192.0.2.25"),
			})
		}
		_ = w.WriteMsg(m)
	})
	mux.HandleFunc("25.2.0.192.in-addr.arpa.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.PTR{
			Hdr: dns.RR_Header{Name: "25.2.0.192.in-addr.arpa.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
			Ptr: "mail.ptr.test.",
		})
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()
	testResolver := useMockResolver(t, addr)

	ptr, err := scanner.ReverseLookupPTR(context.Background(), testResolver, "ptr.test")
	require.NoError(t, err)
	assert.Equal(t, "mail.ptr.test.", ptr)
}

func TestCheckDNSBL_RequiresIPv4(t *testing.T) {
	_, err := scanner.CheckDNSBLWithServer(context.Background(), testResolver,
		net.ParseIP("2001:db8::1"), "zen.spamhaus.org", "127.0.0.1:53")
	assert.EqualError(t, err, "error: no IPv4 address for DNSBL check")
}

func TestValidatePublicSuffix(t *testing.T) {
	ctx := context.Background()

	isSuffix, err := scanner.ValidatePublicSuffix(ctx, "com")
	require.NoError(t, err)
	assert.True(t, isSuffix)

	isSuffix, err = scanner.ValidatePublicSuffix(ctx, "example.com")
	require.NoError(t, err)
	assert.False(t, isSuffix)
}
