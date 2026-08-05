package audit

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vantage "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/finding"
)

// This is the end-to-end test the AXFR check most needed and least had.
//
// The scanner tests prove that a transfer can be performed and a refusal
// recognised; the analyse tests prove the judgement. Neither exercises the path
// between them — discovering the NS set, resolving each server, attempting the
// transfer and turning the result into a finding — which is exactly the seam
// where every boundary defect in this project's history has lived.
//
// It also stands in for a live positive case. No publicly-authorised open AXFR
// server could be reached (zonetransfer.me's nameservers answer ordinary
// queries but silently drop AXFR, as dig confirms), so a mock serving a real
// zone over TCP is the strongest available evidence that the disclosure path
// works rather than merely compiling.

// serveZone starts a UDP resolver answering NS and A queries, and a TCP server
// that hands over a zone, wiring both together so a check can run against them.
func serveZone(t *testing.T, transferable bool) {
	t.Helper()

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(tcp.Addr().String())
	require.NoError(t, err)

	soa, err := dns.NewRR("example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 2026080301 7200 3600 1209600 3600")
	require.NoError(t, err)
	host, err := dns.NewRR("secret-admin.example.test. 3600 IN A 10.0.0.7")
	require.NoError(t, err)

	axfr := &dns.Server{Listener: tcp, Net: "tcp", Handler: dns.HandlerFunc(
		func(w dns.ResponseWriter, r *dns.Msg) {
			if !transferable {
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				_ = w.WriteMsg(m)
				return
			}
			transfer := new(dns.Transfer)
			ch := make(chan *dns.Envelope)
			go func() {
				ch <- &dns.Envelope{RR: []dns.RR{soa, host, soa}}
				close(ch)
			}()
			_ = transfer.Out(w, r, ch)
		})}
	go func() { _ = axfr.ActivateAndServe() }()
	t.Cleanup(func() { _ = axfr.Shutdown() })

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	resolver := &dns.Server{PacketConn: udp, Handler: dns.HandlerFunc(
		func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			q := r.Question[0]

			switch {
			case q.Name == "example.test." && q.Qtype == dns.TypeNS:
				ns, _ := dns.NewRR("example.test. 3600 IN NS ns1.example.test.")
				m.Answer = append(m.Answer, ns)
			case q.Name == "ns1.example.test." && q.Qtype == dns.TypeA:
				a, _ := dns.NewRR("ns1.example.test. 3600 IN A 127.0.0.1")
				m.Answer = append(m.Answer, a)
			}
			_ = w.WriteMsg(m)
		})}
	go func() { _ = resolver.ActivateAndServe() }()
	t.Cleanup(func() { _ = resolver.Shutdown() })

	testClient = vantage.NewClient(vantage.Config{Servers: []string{udp.LocalAddr().String()}})

	original := zoneTransferPort
	zoneTransferPort = port
	t.Cleanup(func() { zoneTransferPort = original })
}

func TestZoneTransferCheckReportsDisclosure(t *testing.T) {
	serveZone(t, true)

	check, ok := Lookup("axfr")
	require.True(t, ok)

	out, err := check.Run(context.Background(), Target{
		Domain: "example.test", Cache: NewCache(testClient),
	})
	require.NoError(t, err)
	require.Equal(t, finding.StateOK, out.State)

	require.Len(t, out.Findings, 1)
	assert.Equal(t, "SURF-AXFR-001", out.Findings[0].ID)

	// The finding must prove the disclosure through evidence a reader can
	// check, not merely assert it.
	var evidence string
	for _, e := range out.Findings[0].Evidence {
		evidence += e.Name + "=" + e.Value + " "
	}
	assert.Contains(t, evidence, "axfr.records=3")
	assert.Contains(t, evidence, "axfr.serial=2026080301")
	assert.Contains(t, evidence, "secret-admin.example.test")
}

func TestZoneTransferCheckReportsRefusal(t *testing.T) {
	serveZone(t, false)

	check, ok := Lookup("axfr")
	require.True(t, ok)

	out, err := check.Run(context.Background(), Target{
		Domain: "example.test", Cache: NewCache(testClient),
	})

	// A refusal is the control working: no findings, but the check completed
	// and says so. This is the case that must never be confused with the one
	// below.
	require.NoError(t, err)
	assert.Equal(t, finding.StateOK, out.State)
	assert.Empty(t, out.Findings)
	require.Len(t, out.Records, 1)
	assert.Contains(t, out.Records[0], "refused")
}

// The converse, and the defect that shipped before this test existed: a zone
// nobody could test must never be reported as a zone that passed.
func TestZoneTransferCheckFailsWhenNoServerAnswers(t *testing.T) {
	serveZone(t, false)

	// Point the transfer at a port nothing is listening on, leaving the
	// resolver intact so the NS set is still discovered.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(closed.Addr().String())
	require.NoError(t, err)
	require.NoError(t, closed.Close())
	zoneTransferPort = port

	check, ok := Lookup("axfr")
	require.True(t, ok)

	out, err := check.Run(context.Background(), Target{
		Domain: "example.test", Cache: NewCache(testClient),
	})

	require.Error(t, err)
	assert.Equal(t, finding.StateCheckFailed, out.State)
	assert.Empty(t, out.Findings)
	// The evidence of what was attempted must survive the failure.
	require.NotEmpty(t, out.Records)
	assert.Contains(t, out.Records[0], "no answer")
}
