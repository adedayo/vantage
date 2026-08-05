package scanner_test

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/scanner"
)

// startMockDNS starts a local mock DNS server on a random UDP port and returns
// the server address and a stop function.
func startMockDNS(t *testing.T, mux *dns.ServeMux) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr = pc.LocalAddr().String()

	srv := &dns.Server{PacketConn: pc, Net: "udp", Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()

	return addr, func() { _ = srv.Shutdown() }
}

// patchResolver temporarily overrides the system resolver used inside scanner
// by monkey-patching /etc/resolv.conf is not feasible; instead we expose a
// test-friendly helper that accepts a custom server address.
// Because scanner.go reads /etc/resolv.conf we spin up a real local server and
// rely on the fact that the test can call the scanner functions directly via
// an exported wrapper that accepts a custom resolver.
//
// For functions that use net.LookupIP (OS resolver) we test the logic layer only.

// ---------- SPF ----------

func TestLookupSPF_NotFound(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("example.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeSuccess // no answer records
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	_, err := scanner.LookupSPFWithServer(context.Background(), testResolver, "example.test", addr)
	assert.Error(t, err)
}

func TestLookupSPF_Found(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("spf.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		rr := &dns.TXT{
			Hdr: dns.RR_Header{Name: "spf.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
			Txt: []string{"v=spf1 include:_spf.google.com ~all"},
		}
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	result, err := scanner.LookupSPFWithServer(context.Background(), testResolver, "spf.test", addr)
	require.NoError(t, err)
	assert.Contains(t, result, "v=spf1")
}

// ---------- DMARC ----------

func TestLookupDMARC_Reject(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("_dmarc.secure.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		rr := &dns.TXT{
			Hdr: dns.RR_Header{Name: "_dmarc.secure.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
			Txt: []string{"v=DMARC1; p=reject; rua=mailto:dmarc@secure.test"},
		}
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	policy, err := scanner.LookupDMARCWithServer(context.Background(), testResolver, "secure.test", addr)
	require.NoError(t, err)
	assert.Equal(t, "reject", policy)
}

func TestLookupDMARC_NotFound(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("_dmarc.none.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	_, err := scanner.LookupDMARCWithServer(context.Background(), testResolver, "none.test", addr)
	assert.Error(t, err)
}

// ---------- DMARC Reporting ----------

func TestParseDMARCReporting(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("_dmarc.report.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		rr := &dns.TXT{
			Hdr: dns.RR_Header{Name: "_dmarc.report.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
			Txt: []string{"v=DMARC1; p=quarantine; rua=mailto:agg@report.test; ruf=mailto:fail@report.test"},
		}
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	rua, ruf, err := scanner.ParseDMARCReportingWithServer(context.Background(), testResolver, "report.test", addr)
	require.NoError(t, err)
	assert.Equal(t, []string{"mailto:agg@report.test"}, rua)
	assert.Equal(t, []string{"mailto:fail@report.test"}, ruf)
}

// ---------- MTA-STS ----------

func TestCheckMTASts_Found(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("_mta-sts.sts.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		rr := &dns.TXT{
			Hdr: dns.RR_Header{Name: "_mta-sts.sts.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
			Txt: []string{"v=STSv1; id=20240101000000Z"},
		}
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	result, err := scanner.CheckMTAStsWithServer(context.Background(), testResolver, "sts.test", addr)
	require.NoError(t, err)
	assert.Contains(t, result, "STSv1")
}

// ---------- CAA ----------

func TestLookupCAA_Found(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("caa.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		rr := &dns.CAA{
			Hdr:   dns.RR_Header{Name: "caa.test.", Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 300},
			Flag:  0,
			Tag:   "issue",
			Value: "letsencrypt.org",
		}
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	records, err := scanner.LookupCAAWithServer(context.Background(), testResolver, "caa.test", addr)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "0 issue letsencrypt.org", records[0])
}

func TestLookupCAA_NotFound(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("nocaa.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	_, err := scanner.LookupCAAWithServer(context.Background(), testResolver, "nocaa.test", addr)
	assert.Error(t, err)
}

// ---------- TLSA HTTPS ----------

func TestLookupTLSAHTTPS_Found(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("_443._tcp.https.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		rr := &dns.TLSA{
			Hdr:          dns.RR_Header{Name: "_443._tcp.https.test.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
			Usage:        3,
			Selector:     1,
			MatchingType: 1,
			Certificate:  "aabbccdd",
		}
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	result, err := scanner.LookupTLSAHTTPSWithServer(context.Background(), testResolver, "https.test", addr)
	require.NoError(t, err)
	assert.Contains(t, result, "3 1 1")
}

// ---------- TLSA SSH ----------

func TestLookupTLSASSH_Found(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("_22._tcp.ssh.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		rr := &dns.TLSA{
			Hdr:          dns.RR_Header{Name: "_22._tcp.ssh.test.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
			Usage:        3,
			Selector:     1,
			MatchingType: 2,
			Certificate:  "deadbeef",
		}
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	result, err := scanner.LookupTLSASSHWithServer(context.Background(), testResolver, "ssh.test", addr)
	require.NoError(t, err)
	assert.Contains(t, result, "3 1 2")
}

// ---------- SMTP DANE ----------

func TestLookupTLASSMTP_Found(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("_25._tcp.smtp.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		rr := &dns.TLSA{
			Hdr:          dns.RR_Header{Name: "_25._tcp.smtp.test.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
			Usage:        2,
			Selector:     0,
			MatchingType: 1,
			Certificate:  "cafebabe",
		}
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	result, err := scanner.LookupTLASSMTPWithServer(context.Background(), testResolver, "smtp.test", addr)
	require.NoError(t, err)
	assert.Contains(t, result, "2 0 1")
}

// ---------- DNSSEC / NSSEC ----------

func TestVerifyNSSEC_Found(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("nsec.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeNSEC {
			rr := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "nsec.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: "z.nsec.test.",
				TypeBitMap: []uint16{dns.TypeA},
			}
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	found, err := scanner.VerifyNSSECWithServer(context.Background(), testResolver, "nsec.test", addr)
	require.NoError(t, err)
	assert.True(t, found)
}

func TestVerifyNSSEC_NotFound(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("nodnssec.test.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	found, err := scanner.VerifyNSSECWithServer(context.Background(), testResolver, "nodnssec.test", addr)
	require.NoError(t, err)
	assert.False(t, found)
}

// ---------- ValidatePublicSuffix ----------

func TestValidatePublicSuffix_IsPublicSuffix(t *testing.T) {
	ctx := context.Background()
	// "com" is a public suffix
	isPS, err := scanner.ValidatePublicSuffix(ctx, "com")
	require.NoError(t, err)
	assert.True(t, isPS)
}

func TestValidatePublicSuffix_IsNotPublicSuffix(t *testing.T) {
	ctx := context.Background()
	// "example.com" is not a public suffix itself
	isPS, err := scanner.ValidatePublicSuffix(ctx, "example.com")
	require.NoError(t, err)
	assert.False(t, isPS)
}

// ---------- DNSBL ----------

// TestCheckDNSBL_Listed mocks the DNSBL A query for a reversed IP.
// We use 127.0.0.2 (loopback) directly as the domain here is a raw IP string.
// Because CheckDNSBL calls net.LookupIP we test the query logic via a
// server-parameterised helper.
func TestCheckDNSBL_Listed(t *testing.T) {
	blocklist := "zen.spamhaus.org"
	// Build the DNSBL name for 127.0.0.2
	dnsblName := fmt.Sprintf("2.0.0.127.%s.", blocklist)
	mux := dns.NewServeMux()
	mux.HandleFunc(dnsblName, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		rr := &dns.A{
			Hdr: dns.RR_Header{Name: dnsblName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("127.0.0.2"),
		}
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	// Pass IP directly (bypassing net.LookupIP)
	listed, err := scanner.CheckDNSBLWithServer(context.Background(), testResolver, net.ParseIP("127.0.0.2"), blocklist, addr)
	require.NoError(t, err)
	assert.True(t, listed)
}

func TestCheckDNSBL_NotListed(t *testing.T) {
	blocklist := "zen.spamhaus.org"
	dnsblName := fmt.Sprintf("2.0.0.127.%s.", blocklist)
	mux := dns.NewServeMux()
	mux.HandleFunc(dnsblName, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError // NXDOMAIN = not listed
		_ = w.WriteMsg(m)
	})
	addr, stop := startMockDNS(t, mux)
	defer stop()

	listed, err := scanner.CheckDNSBLWithServer(context.Background(), testResolver, net.ParseIP("127.0.0.2"), blocklist, addr)
	require.NoError(t, err)
	assert.False(t, listed)
}
