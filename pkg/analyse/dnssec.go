package analyse

// dnssec.go assesses a zone's DNSSEC posture from the records retrieved for it.
//
// The distinction this file exists to draw is between "the zone is signed" and
// "the zone validates". A DNSKEY at the apex proves only the former. Without a
// DS record at the parent no validating resolver ever reaches those keys, and
// the signatures — however carefully generated — protect nobody. The opposite
// case is worse still: a DS with no matching key makes the entire zone fail to
// resolve for every validating resolver on the internet, which is an outage,
// not a weakness.

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/adedayo/vantage/pkg/finding"
)

// RRSIGExpiryWarning is how close to expiry a signature may come before it is
// reported. Seven days is the shortest window in which a human operator can
// realistically notice and act: shorter, and the first anyone hears of it is
// the zone going dark.
const RRSIGExpiryWarning = 7 * 24 * time.Hour

// MinRSAKeyBits is the smallest RSA key size current guidance accepts for
// DNSSEC signing.
const MinRSAKeyBits = 2048

// DNSKEY is a parsed DNSKEY record.
type DNSKEY struct {
	// KeyTag is the RFC 4034 §B key tag, the value a DS record refers to.
	KeyTag uint16
	// Flags carries the zone-key (bit 7) and secure-entry-point (bit 15) bits.
	Flags uint16
	// Algorithm is the RFC 8624 algorithm number.
	Algorithm uint8
	// PublicKey is the base64 key material, used to derive the RSA key size.
	PublicKey string
}

// IsZoneKey reports whether the zone-key flag is set, i.e. the key signs the
// zone's records rather than being some other kind of key.
func (k DNSKEY) IsZoneKey() bool { return k.Flags&0x0100 != 0 }

// IsSecureEntryPoint reports whether the SEP bit is set, which by convention
// marks a key-signing key — the key a DS record should point at.
func (k DNSKEY) IsSecureEntryPoint() bool { return k.Flags&0x0001 != 0 }

// DS is a parsed delegation signer record, published by the parent zone.
type DS struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	// DigestMismatch is set only when the digest was recomputed from a DNSKEY
	// with the same key tag and algorithm and did not match. It is deliberately
	// false by default, so a collector that cannot verify digests never causes
	// a broken-chain finding it has not actually evidenced.
	DigestMismatch bool
}

// RRSIG is a parsed signature record.
type RRSIG struct {
	// TypeCovered names the record type the signature protects, e.g. "SOA".
	TypeCovered string
	Algorithm   uint8
	KeyTag      uint16
	SignerName  string
	Expiration  time.Time
	Inception   time.Time
}

// DNSSECZone is the evidence gathered about one zone's DNSSEC deployment.
type DNSSECZone struct {
	// Keys are the DNSKEY records at the apex.
	Keys []DNSKEY
	// DS are the delegation signer records held by the parent.
	DS []DS
	// Signatures are the RRSIG records observed, from any queried name.
	Signatures []RRSIG
	// NSEC and NSEC3 report which form of authenticated denial the zone uses.
	NSEC  bool
	NSEC3 bool
	// NSECSynthesised is set when the NSEC records are generated per query and
	// cover only the queried name, rather than chaining the zone's real
	// contents. Several large providers answer this way, and the chain cannot
	// be walked, so the zone-walking finding must not be raised for them.
	NSECSynthesised bool
	// NSEC3Iterations is the extra hash iteration count from NSEC3 or
	// NSEC3PARAM. RFC 9276 requires zero.
	NSEC3Iterations int
	// AuthenticatedData reports whether the answering resolver set the AD bit,
	// which distinguishes "the zone is signed" from "my resolver validates it".
	AuthenticatedData bool
	// Source names the resolver that answered, for evidence attribution.
	Source string
	// Now allows tests to fix the clock used for expiry arithmetic. The zero
	// value means the current time.
	Now time.Time
}

// Signed reports whether the zone published any DNSSEC material at all.
func (z DNSSECZone) Signed() bool { return len(z.Keys) > 0 || len(z.DS) > 0 }

// now returns the reference time for expiry arithmetic.
func (z DNSSECZone) now() time.Time {
	if z.Now.IsZero() {
		return time.Now()
	}
	return z.Now
}

// weakAlgorithms are the signing algorithms RFC 8624 marks MUST NOT or NOT
// RECOMMENDED for signing, mapped to the name used in evidence.
//
// SHA-1 based algorithms (5 and 7) are the significant entry: chosen-prefix
// collisions against SHA-1 are practical, so the signatures they produce no
// longer carry the assurance the zone operator believes they do.
var weakAlgorithms = map[uint8]string{
	1:  "RSAMD5",
	3:  "DSA",
	5:  "RSASHA1",
	6:  "DSA-NSEC3-SHA1",
	7:  "RSASHA1-NSEC3-SHA1",
	12: "ECC-GOST",
}

// rsaAlgorithms are the algorithms whose key material is an RSA public key in
// RFC 3110 form, and for which a modulus size can therefore be derived.
var rsaAlgorithms = map[uint8]bool{1: true, 5: true, 7: true, 8: true, 10: true}

// AlgorithmName returns a readable name for a DNSSEC algorithm number.
func AlgorithmName(algorithm uint8) string {
	names := map[uint8]string{
		1: "RSAMD5", 3: "DSA", 5: "RSASHA1", 6: "DSA-NSEC3-SHA1",
		7: "RSASHA1-NSEC3-SHA1", 8: "RSASHA256", 10: "RSASHA512",
		12: "ECC-GOST", 13: "ECDSAP256SHA256", 14: "ECDSAP384SHA384",
		15: "ED25519", 16: "ED448",
	}
	if name, ok := names[algorithm]; ok {
		return name
	}
	return fmt.Sprintf("algorithm %d", algorithm)
}

// KeyBits returns the RSA modulus size in bits, or 0 when the key is not RSA
// or the material cannot be parsed.
//
// The wire format is RFC 3110 §2: a one-byte exponent length, or a zero byte
// followed by a two-byte length, then the exponent, then the modulus. Only RSA
// has a size worth reporting — the elliptic-curve and Edwards algorithms have
// one size each, fixed by the algorithm number.
func (k DNSKEY) KeyBits() int {
	if !rsaAlgorithms[k.Algorithm] {
		return 0
	}

	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(k.PublicKey), ""))
	if err != nil || len(raw) < 3 {
		return 0
	}

	expLen, offset := int(raw[0]), 1
	if expLen == 0 {
		expLen = int(raw[1])<<8 | int(raw[2])
		offset = 3
	}
	if expLen == 0 || offset+expLen >= len(raw) {
		return 0
	}

	modulus := raw[offset+expLen:]
	// Leading zero octets are padding, not key material, and counting them
	// would overstate the key size by a whole byte at a time.
	for len(modulus) > 0 && modulus[0] == 0 {
		modulus = modulus[1:]
	}
	return len(modulus) * 8
}

// matchesDS reports whether a key is the one a DS record delegates to.
//
// Key tag and algorithm are what a validator uses to select candidate keys.
// Where the collector was able to recompute the digest and it disagreed, the
// pairing is rejected: matching tags with a mismatched digest is precisely the
// broken chain worth reporting, not evidence of a working one.
func matchesDS(k DNSKEY, ds DS) bool {
	return k.KeyTag == ds.KeyTag && k.Algorithm == ds.Algorithm && !ds.DigestMismatch
}

// DNSSEC evaluates a zone's chain of trust, algorithm choices, signature
// validity window and denial-of-existence strategy.
func DNSSEC(o Origin, z DNSSECZone) []finding.Finding {
	target := o.Target
	source := z.Source
	if source == "" {
		source = o.Source
	}

	// Every finding carries the resolver's AD bit, because "signed" and
	// "validated by the resolver in front of the user" are different claims and
	// conflating them is the most common misreading of a DNSSEC report.
	adEvidence := finding.ComputedEvidence("dnssec.resolver_ad",
		fmt.Sprintf("%t", z.AuthenticatedData))

	if !z.Signed() {
		return []finding.Finding{
			finding.New("SURF-DNSSEC-001", target, adEvidence,
				finding.DNSEvidence(target, "DNSKEY", "no DNSKEY or DS records", source)),
		}
	}

	var findings []finding.Finding
	findings = append(findings, chainFindings(target, source, z, adEvidence)...)
	findings = append(findings, algorithmFindings(target, source, z, adEvidence)...)
	findings = append(findings, signatureFindings(target, source, z, adEvidence)...)
	findings = append(findings, denialFindings(target, source, z, adEvidence)...)
	return findings
}

// chainFindings assesses the link between the zone's keys and the parent's DS.
func chainFindings(target, source string, z DNSSECZone, ad finding.Evidence) []finding.Finding {
	switch {
	case len(z.DS) == 0:
		return []finding.Finding{
			finding.New("SURF-DNSSEC-002", target, ad,
				finding.DNSEvidence(target, "DNSKEY", keySummary(z.Keys), source),
				finding.DNSEvidence(target, "DS", "no DS record at the parent", source)),
		}

	case len(z.Keys) == 0:
		// The parent delegates to keys the zone does not publish. Every
		// validating resolver returns SERVFAIL, so the domain is unreachable
		// for a large and growing share of the internet.
		return []finding.Finding{
			finding.New("SURF-DNSSEC-003", target, ad,
				finding.DNSEvidence(target, "DS", dsSummary(z.DS), source),
				finding.DNSEvidence(target, "DNSKEY", "no DNSKEY records published", source)),
		}
	}

	for _, ds := range z.DS {
		for _, k := range z.Keys {
			if matchesDS(k, ds) {
				return nil
			}
		}
	}

	return []finding.Finding{
		finding.New("SURF-DNSSEC-003", target, ad,
			finding.DNSEvidence(target, "DS", dsSummary(z.DS), source),
			finding.DNSEvidence(target, "DNSKEY", keySummary(z.Keys), source)),
	}
}

// algorithmFindings reports weak signing algorithms and undersized RSA keys.
func algorithmFindings(target, source string, z DNSSECZone, ad finding.Evidence) []finding.Finding {
	var reasons []string
	seen := map[string]bool{}

	note := func(reason string) {
		if !seen[reason] {
			seen[reason] = true
			reasons = append(reasons, reason)
		}
	}

	for _, k := range z.Keys {
		if name, weak := weakAlgorithms[k.Algorithm]; weak {
			note(fmt.Sprintf("key %d uses %s", k.KeyTag, name))
		}
		if bits := k.KeyBits(); bits > 0 && bits < MinRSAKeyBits {
			note(fmt.Sprintf("key %d is %d-bit RSA", k.KeyTag, bits))
		}
	}
	// A DS may name an algorithm the zone no longer publishes a key for, and a
	// weak one there is equally a weak link in the chain.
	for _, ds := range z.DS {
		if name, weak := weakAlgorithms[ds.Algorithm]; weak {
			note(fmt.Sprintf("DS for key %d uses %s", ds.KeyTag, name))
		}
	}

	if len(reasons) == 0 {
		return nil
	}
	sort.Strings(reasons)
	return []finding.Finding{
		finding.New("SURF-DNSSEC-004", target, ad,
			finding.ComputedEvidence("dnssec.weak_algorithms", strings.Join(reasons, "; ")),
			finding.DNSEvidence(target, "DNSKEY", keySummary(z.Keys), source)).
			WithDescription("Specifically, " + strings.Join(reasons, "; ") + "."),
	}
}

// signatureFindings reports expired and imminently expiring signatures.
//
// Only the earliest offending signature is reported for each condition. A zone
// resigns everything on one schedule, so listing every RRSIG would produce
// dozens of findings describing a single operational fault.
func signatureFindings(target, source string, z DNSSECZone, ad finding.Evidence) []finding.Finding {
	now := z.now()

	var expired, expiring *RRSIG
	for i := range z.Signatures {
		sig := z.Signatures[i]
		if sig.Expiration.IsZero() {
			continue
		}
		switch {
		case !sig.Expiration.After(now):
			if expired == nil || sig.Expiration.Before(expired.Expiration) {
				expired = &z.Signatures[i]
			}
		case sig.Expiration.Sub(now) <= RRSIGExpiryWarning:
			if expiring == nil || sig.Expiration.Before(expiring.Expiration) {
				expiring = &z.Signatures[i]
			}
		}
	}

	var findings []finding.Finding
	if expired != nil {
		findings = append(findings, finding.New("SURF-DNSSEC-006", target, ad,
			finding.DNSEvidence(target, "RRSIG", signatureSummary(*expired), source),
			finding.ComputedEvidence("dnssec.expired_for",
				now.Sub(expired.Expiration).Round(time.Minute).String())).
			WithDescription("Specifically, the earliest expired signature covers the `"+
				expired.TypeCovered+"` record set, signed by key tag "+
				strconv.Itoa(int(expired.KeyTag))+"."))
	}
	if expiring != nil {
		findings = append(findings, finding.New("SURF-DNSSEC-005", target, ad,
			finding.DNSEvidence(target, "RRSIG", signatureSummary(*expiring), source),
			finding.ComputedEvidence("dnssec.expires_in",
				expiring.Expiration.Sub(now).Round(time.Minute).String())).
			WithDescription("Specifically, the earliest expiring signature covers the `"+
				expiring.TypeCovered+"` record set, signed by key tag "+
				strconv.Itoa(int(expiring.KeyTag))+"."))
	}
	return findings
}

// denialFindings assesses the authenticated denial-of-existence strategy.
func denialFindings(target, source string, z DNSSECZone, ad finding.Evidence) []finding.Finding {
	var findings []finding.Finding

	if z.NSEC && !z.NSEC3 && !z.NSECSynthesised {
		findings = append(findings, finding.New("SURF-DNSSEC-007", target, ad,
			finding.DNSEvidence(target, "NSEC", "zone uses NSEC for denial of existence", source)))
	}

	if z.NSEC3 && z.NSEC3Iterations > 0 {
		findings = append(findings, finding.New("SURF-DNSSEC-008", target, ad,
			finding.DNSEvidence(target, "NSEC3",
				fmt.Sprintf("%d extra iterations", z.NSEC3Iterations), source)))
	}

	return findings
}

// keySummary renders the key set for evidence.
func keySummary(keys []DNSKEY) string {
	if len(keys) == 0 {
		return "no DNSKEY records published"
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		part := fmt.Sprintf("keytag %d %s", k.KeyTag, AlgorithmName(k.Algorithm))
		if bits := k.KeyBits(); bits > 0 {
			part += fmt.Sprintf(" %d-bit", bits)
		}
		if k.IsSecureEntryPoint() {
			part += " (KSK)"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
}

// dsSummary renders the DS set for evidence.
func dsSummary(records []DS) string {
	parts := make([]string, 0, len(records))
	for _, ds := range records {
		part := fmt.Sprintf("keytag %d %s digest %d",
			ds.KeyTag, AlgorithmName(ds.Algorithm), ds.DigestType)
		if ds.DigestMismatch {
			part += " (digest does not match the published key)"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
}

// signatureSummary renders one RRSIG for evidence.
func signatureSummary(sig RRSIG) string {
	return fmt.Sprintf("%s RRSIG by keytag %d, expires %s",
		sig.TypeCovered, sig.KeyTag, sig.Expiration.UTC().Format(time.RFC3339))
}

// DNSSECRecords renders a zone as the human-readable record list the CLI and
// the audit result present as retrieved evidence.
func DNSSECRecords(z DNSSECZone) []string {
	if !z.Signed() {
		return nil
	}

	records := []string{"DNSKEY: " + keySummary(z.Keys)}
	if len(z.DS) > 0 {
		records = append(records, "DS: "+dsSummary(z.DS))
	} else {
		records = append(records, "DS: none at the parent")
	}
	for _, sig := range z.Signatures {
		records = append(records, "RRSIG: "+signatureSummary(sig))
	}
	switch {
	case z.NSEC3:
		records = append(records,
			fmt.Sprintf("Denial of existence: NSEC3, %d iterations", z.NSEC3Iterations))
	case z.NSEC && z.NSECSynthesised:
		records = append(records, "Denial of existence: NSEC, synthesised per query")
	case z.NSEC:
		records = append(records, "Denial of existence: NSEC")
	}
	records = append(records,
		fmt.Sprintf("Resolver AD bit: %t", z.AuthenticatedData))
	return records
}
