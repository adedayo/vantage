package analyse

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adedayo/vantage/pkg/finding"
)

// These tests guard a property rather than a wording: when a check looks at a
// set of items and faults one of them, the finding must say which. The rule
// that makes this worth enforcing is that the reader's next action is always
// "fix that item", and a finding that withholds the item's name makes them
// derive it from evidence before they can act.
//
// The assertions therefore look for the offending item in the description and
// never for the sentence that carries it. Wording is expected to be revised;
// the guarantee that the item is named is not.

func descriptionFor(t *testing.T, findings []finding.Finding, id string) string {
	t.Helper()
	for _, f := range findings {
		if f.ID == id {
			return f.Description
		}
	}
	require.Failf(t, "finding not produced", "no %s in %d findings", id, len(findings))
	return ""
}

// assertNames checks that a finding exists and that its description points at
// every item the reader has to act on.
func assertNames(t *testing.T, findings []finding.Finding, id string, items ...string) {
	t.Helper()
	got := descriptionFor(t, findings, id)
	for _, item := range items {
		assert.Containsf(t, got, item,
			"%s must name %q in its description, not only in its evidence", id, item)
	}
}

// --- SPF -------------------------------------------------------------------

func TestSPFFindingsNameTheOffendingTerm(t *testing.T) {
	o := Origin{Target: "example.com"}
	record := "v=spf1 ptr ip4:10.0.0.0/8 -all"

	findings := SPF(o, []string{record}, true)

	assertNames(t, findings, "SURF-SPF-008", "ptr")
	assertNames(t, findings, "SURF-SPF-011", "10.0.0.0/8")
}

// SURF-SPF-009 is the case that prompted all of this: the record in the
// evidence is long enough that the broken include was effectively hidden.
func TestSPFEvalFindingsNameTheBrokenInclude(t *testing.T) {
	record := "v=spf1 include:live.example.net include:dead.example.net -all"
	f := &fakeResolver{
		txt: map[string][]string{
			"example.com":      {record},
			"live.example.net": {"v=spf1 ip4:192.0.2.1 -all"},
		},
		hosts: map[string]bool{"example.com": true},
	}

	findings, _ := SPFObserved(context.Background(), Origin{Target: "example.com"},
		f, []string{record}, true)

	assertNames(t, findings, "SURF-SPF-009", "dead.example.net")
	// The working include must not be named: a finding that lists both terms
	// tells the reader no more than the record already did.
	assert.NotContains(t, descriptionFor(t, findings, "SURF-SPF-009"), "live.example.net")
}

func TestSPFEvalFindingNamesTheLoopedDomain(t *testing.T) {
	record := "v=spf1 include:loop.example.net -all"
	f := &fakeResolver{
		txt: map[string][]string{
			"example.com":      {record},
			"loop.example.net": {"v=spf1 include:loop.example.net -all"},
		},
		hosts: map[string]bool{"example.com": true},
	}

	findings, _ := SPFObserved(context.Background(), Origin{Target: "example.com"},
		f, []string{record}, true)

	assertNames(t, findings, "SURF-SPF-009", "loop.example.net")
}

func TestSPFEvalVoidLookupFindingNamesTheDeadNames(t *testing.T) {
	record := "v=spf1 a:gone1.example.net a:gone2.example.net a:gone3.example.net -all"
	f := &fakeResolver{
		txt:   map[string][]string{"example.com": {record}},
		hosts: map[string]bool{},
	}

	findings, _ := SPFObserved(context.Background(), Origin{Target: "example.com"},
		f, []string{record}, true)

	assertNames(t, findings, "SURF-SPF-007",
		"gone1.example.net", "gone2.example.net", "gone3.example.net")
}

func TestSPFEvalLengthFindingNamesTheBreach(t *testing.T) {
	record := "v=spf1 " + strings.Repeat("ip4:192.0.2.1 ", 60) + "-all"
	require.Greater(t, len(record), 512)

	f := &fakeResolver{
		txt:   map[string][]string{"example.com": {record}},
		hosts: map[string]bool{"example.com": true},
	}

	findings, _ := SPFObserved(context.Background(), Origin{Target: "example.com"},
		f, []string{record}, true)

	// The description must state the measurement, not merely that one exists.
	assertNames(t, findings, "SURF-SPF-010", "octets")
}

// --- DKIM ------------------------------------------------------------------

func TestDKIMFindingsNameTheSelector(t *testing.T) {
	o := Origin{Target: "example.com"}
	keys := []DKIMKey{
		{Selector: "weak", Raw: "v=DKIM1; p=AAAA", Bits: 512, Valid: true},
		{Selector: "legacy", Raw: "v=DKIM1; p=AAAA", Bits: 1024, Valid: true},
		{Selector: "testing", Raw: "v=DKIM1; t=y; p=AAAA", Bits: 2048, Valid: true, TestMode: true},
		{Selector: "retired", Raw: "v=DKIM1; p=", Valid: true, Revoked: true},
		{Selector: "broken", Raw: "not a key", Reason: "the record has no p= tag"},
	}

	findings := DKIM(o, keys, false)

	assertNames(t, findings, "SURF-DKIM-002", "`weak`")
	assertNames(t, findings, "SURF-DKIM-003", "`legacy`")
	assertNames(t, findings, "SURF-DKIM-004", "`retired`")
	assertNames(t, findings, "SURF-DKIM-005", "`testing`")
	assertNames(t, findings, "SURF-DKIM-006", "`broken`", "no p= tag")
}

// --- MX --------------------------------------------------------------------

func TestMXFindingsNameTheOffendingExchanger(t *testing.T) {
	o := Origin{Target: "example.com"}
	hosts := []MXHost{
		{Preference: 10, Host: "good.example.net", Resolves: true},
		{Preference: 20, Host: "missing.example.net"},
		{Preference: 30, Host: "alias.example.net", Resolves: true, IsCNAME: true},
	}

	findings := MX(o, hosts, true)

	assertNames(t, findings, "SURF-MX-001", "`missing.example.net`")
	assertNames(t, findings, "SURF-MX-002", "`alias.example.net`")
}

// --- Delegation ------------------------------------------------------------

func TestDelegationFindingsNameTheNameserver(t *testing.T) {
	o := Origin{Target: "example.com"}
	d := Delegation{
		Domain:        "example.com",
		ParentChecked: true,
		ParentNS:      []string{"ns1.example.com", "ns2.provider.net", "ns3.provider.net"},
		Glue:          map[string][]string{},
		Nameservers: []Nameserver{
			// In-bailiwick with no glue, and lame into the bargain.
			{Host: "ns1.example.com", Provider: "example.com", Answered: true},
			{Host: "ns2.provider.net", Provider: "provider.net",
				Answered: true, Authoritative: true,
				RecursionTested: true, OpenRecursive: true},
			{Host: "ns3.provider.net", Provider: "provider.net",
				Answered: true, Authoritative: true},
		},
	}

	findings := DelegationHygiene(o, d)

	assertNames(t, findings, "SURF-NS-005", "`ns1.example.com`")
	assertNames(t, findings, "SURF-NS-006", "`ns1.example.com`")
	assertNames(t, findings, "SURF-NS-007", "`ns2.provider.net`")
}

// A nameserver that never answered gets a second sentence about reachability.
// It has to read as a continuation of the first, which names the host, rather
// than as a statement about some other server.
func TestLameDelegationCaveatFollowsTheNamedHost(t *testing.T) {
	o := Origin{Target: "example.com"}
	d := Delegation{
		Domain: "example.com",
		Nameservers: []Nameserver{
			{Host: "silent.provider.net", Provider: "provider.net"},
			{Host: "ns2.provider.net", Provider: "provider.net",
				Answered: true, Authoritative: true},
		},
	}

	got := descriptionFor(t, DelegationHygiene(o, d), "SURF-NS-005")

	assert.Contains(t, got, "`silent.provider.net`")
	assert.Contains(t, got, "It did not respond")
	// "The nameserver did not respond" after "A nameserver named in the
	// delegation..." reads as a different server being discussed.
	assert.NotContains(t, got, "The nameserver did not respond")
}

// --- MTA-STS ---------------------------------------------------------------

func TestMTASTSUncoveredFindingNamesTheExchangers(t *testing.T) {
	o := Origin{Target: "example.com"}
	record := "v=STSv1; id=20260101T000000;"
	policy := MTASTSPolicy{
		Mode: "enforce", MX: []string{"covered.example.net"}, MaxAge: 604800,
		Raw: "version: STSv1", Fetched: true, CertificateValid: true, Valid: true,
	}

	findings := MTASTS(o, []string{record}, policy,
		[]string{"covered.example.net", "orphan1.example.net", "orphan2.example.net"})

	assertNames(t, findings, "SURF-MTASTS-005",
		"`orphan1.example.net`", "`orphan2.example.net`")
	assert.NotContains(t, descriptionFor(t, findings, "SURF-MTASTS-005"),
		"`covered.example.net`")
}

// --- DMARC -----------------------------------------------------------------

func TestDMARCReportAuthorisationFindingNamesTheDestination(t *testing.T) {
	record := "v=DMARC1; p=reject; rua=mailto:reports@third-party.example;"
	r := &fakeDMARCResolver{txt: map[string][]string{
		"_dmarc.example.com": {record},
	}}

	findings := DMARCFull(context.Background(), Origin{Target: "example.com"},
		r, []string{record}, "example.com")

	assertNames(t, findings, "SURF-DMARC-006",
		"third-party.example",
		"example.com._report._dmarc.third-party.example")
}

// --- CAA -------------------------------------------------------------------

func TestCAACriticalTagFindingNamesTheTag(t *testing.T) {
	policy := CAAPolicy{
		Source: "example.com",
		Records: []CAARecord{
			{Flags: 0, Tag: "issue", Value: "ca.example"},
			{Flags: 128, Tag: "contactemail", Value: "sec@example.com"},
		},
	}

	findings := CAA(Origin{Target: "example.com"}, policy)

	assertNames(t, findings, "SURF-CAA-004", "`contactemail`")
}

// --- DNSSEC ----------------------------------------------------------------

func TestDNSSECAlgorithmFindingNamesTheWeakKey(t *testing.T) {
	z := DNSSECZone{
		// Algorithm 5 is RSASHA1, which RFC 8624 rules out for signing.
		Keys: []DNSKEY{{KeyTag: 12345, Flags: 0x0101, Algorithm: 5}},
		DS:   []DS{{KeyTag: 12345, Algorithm: 5, DigestType: 2}},
	}

	findings := DNSSEC(Origin{Target: "example.com"}, z)

	assertNames(t, findings, "SURF-DNSSEC-004", "12345", "RSASHA1")
}

func TestDNSSECSignatureFindingsNameTheRecordSet(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	z := DNSSECZone{
		Keys: []DNSKEY{{KeyTag: 12345, Flags: 0x0101, Algorithm: 13}},
		DS:   []DS{{KeyTag: 12345, Algorithm: 13, DigestType: 2}},
		Signatures: []RRSIG{
			{TypeCovered: "SOA", KeyTag: 12345, Expiration: now.Add(-24 * time.Hour)},
			{TypeCovered: "MX", KeyTag: 54321, Expiration: now.Add(48 * time.Hour)},
		},
		Now: now,
	}

	findings := DNSSEC(Origin{Target: "example.com"}, z)

	assertNames(t, findings, "SURF-DNSSEC-006", "`SOA`", "12345")
	assertNames(t, findings, "SURF-DNSSEC-005", "`MX`", "54321")
}

// --- Shared guarantees -----------------------------------------------------

// The description must add to the catalogue text rather than replace it: the
// reader still needs to know why the item matters, not only which it is.
func TestPinpointingKeepsTheCatalogueDescription(t *testing.T) {
	entry, ok := finding.Lookup("SURF-MX-001")
	require.True(t, ok)

	findings := MX(Origin{Target: "example.com"},
		[]MXHost{{Preference: 10, Host: "missing.example.net"}}, true)

	got := descriptionFor(t, findings, "SURF-MX-001")
	assert.True(t, strings.HasPrefix(got, entry.Description),
		"expected the catalogue description to be retained as the prefix")
}

// Naming the item is a change to prose only. Evidence keys are what consumers
// match on, so they must survive untouched.
func TestPinpointingLeavesEvidenceIntact(t *testing.T) {
	findings := MX(Origin{Target: "example.com"},
		[]MXHost{{Preference: 10, Host: "missing.example.net"}}, true)

	for _, f := range findings {
		if f.ID != "SURF-MX-001" {
			continue
		}
		require.Len(t, f.Evidence, 1)
		assert.Equal(t, "mx.host", f.Evidence[0].Name)
		assert.Equal(t, "10 missing.example.net", f.Evidence[0].Value)
		return
	}
	require.Fail(t, "SURF-MX-001 not produced")
}
