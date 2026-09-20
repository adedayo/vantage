package analyse

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/adedayo/vantage/pkg/finding"
)

// DKIMKey is a parsed DKIM key record, together with the selector it was found
// under.
//
// The parse result deliberately records *why* a record is unusable rather than
// returning an error: a malformed key is a finding the operator needs to see,
// not a failure of the tool.
type DKIMKey struct {
	// Selector is the label the key was published under.
	Selector string
	// Raw is the record as retrieved.
	Raw string
	// KeyType is the k= tag, defaulting to "rsa" per RFC 6376.
	KeyType string
	// Bits is the RSA modulus size, or 0 for non-RSA and unparseable keys.
	Bits int
	// Revoked reports an empty p= tag, which RFC 6376 defines as revocation.
	Revoked bool
	// TestMode reports the t=y flag.
	TestMode bool
	// Valid is false when the record cannot serve as a DKIM key.
	Valid bool
	// Reason explains why an invalid record was rejected.
	Reason string
}

// ParseDKIM parses a DKIM key record published at
// <selector>._domainkey.<domain>.
func ParseDKIM(selector, record string) DKIMKey {
	k := DKIMKey{Selector: selector, Raw: strings.TrimSpace(record), KeyType: "rsa"}

	var (
		publicKey string
		sawP      bool
	)
	for _, tag := range strings.Split(k.Raw, ";") {
		key, value, found := strings.Cut(strings.TrimSpace(tag), "=")
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch key {
		case "k":
			k.KeyType = strings.ToLower(value)
		case "p":
			sawP = true
			// Providers and DNS interfaces routinely wrap long keys; the
			// whitespace is presentational and is not part of the base64.
			publicKey = strings.Join(strings.Fields(value), "")
		case "t":
			for _, flag := range strings.Split(strings.ToLower(value), ":") {
				if strings.TrimSpace(flag) == "y" {
					k.TestMode = true
				}
			}
		}
	}

	switch {
	case !sawP:
		k.Reason = "the mandatory p= tag is missing"
		return k
	case publicKey == "":
		// Revocation is well-formed, not malformed: the operator meant it.
		k.Revoked, k.Valid = true, true
		return k
	}

	der, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		k.Reason = "the p= tag is not valid base64"
		return k
	}

	// Ed25519 keys are published as raw 32-byte keys, not SubjectPublicKeyInfo,
	// so they are validated by length rather than by parsing.
	if k.KeyType == "ed25519" {
		if len(der) != ed25519.PublicKeySize {
			k.Reason = "the ed25519 key is " + strconv.Itoa(len(der)) + " bytes, expected 32"
			return k
		}
		k.Valid = true
		return k
	}

	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		k.Reason = "the p= tag does not decode to a well-formed public key"
		return k
	}
	switch pub := parsed.(type) {
	case *rsa.PublicKey:
		k.Bits = pub.N.BitLen()
	case *ecdsa.PublicKey, ed25519.PublicKey:
		// Accepted without a size judgement: the RSA thresholds do not apply.
	}
	k.Valid = true
	return k
}

// DKIM evaluates the DKIM keys found for a domain.
//
// keys holds every record retrieved, one per selector. probed reports whether
// the selectors were guessed from the common list rather than supplied by the
// caller, which governs the confidence attached to an absence: enumeration is
// not proof, and a domain may sign with a selector nobody can guess.
func DKIM(o Origin, keys []DKIMKey, probed bool) []finding.Finding {
	var findings []finding.Finding
	target := o.Target

	usable := 0
	for _, k := range keys {
		if k.Valid && !k.Revoked {
			usable++
		}
	}

	if usable == 0 {
		f := finding.New("SURF-DKIM-001", target,
			o.txtEvidence("*._domainkey."+strings.TrimSuffix(target, "."),
				"no usable DKIM key record found"),
			finding.ComputedEvidence("dkim.selectors_examined", strconv.Itoa(len(keys))))
		if !probed {
			// The caller named the selector, so absence is an observation
			// rather than an inference and can be stated with confidence.
			f = f.WithConfidence(finding.ConfidenceHigh)
		}
		findings = append(findings, f)
	}

	for _, k := range keys {
		name := k.Selector + "._domainkey." + strings.TrimSuffix(target, ".")
		ev := o.txtEvidence(name, k.Raw)
		// A domain commonly publishes several selectors, and the finding is
		// about one of them. Without the selector named in the prose the
		// reader has to recover it from the evidence key, which is the whole
		// record — so the shortest fact is found last.
		selector := "Specifically, this is the `" + k.Selector + "` selector"

		switch {
		case !k.Valid:
			findings = append(findings, finding.New("SURF-DKIM-006", target, ev).
				WithDescription(selector+", where "+k.Reason+"."))
			continue
		case k.Revoked:
			findings = append(findings, finding.New("SURF-DKIM-004", target, ev).
				WithDescription(selector+"."))
			continue
		}

		switch {
		case k.Bits > 0 && k.Bits < 1024:
			findings = append(findings, finding.New("SURF-DKIM-002", target, ev,
				finding.ComputedEvidence("dkim.key_bits", strconv.Itoa(k.Bits))).
				WithDescription(selector+", carrying a "+strconv.Itoa(k.Bits)+"-bit key."))
		case k.Bits == 1024:
			findings = append(findings, finding.New("SURF-DKIM-003", target, ev,
				finding.ComputedEvidence("dkim.key_bits", "1024")).
				WithDescription(selector+"."))
		}

		if k.TestMode {
			findings = append(findings, finding.New("SURF-DKIM-005", target, ev,
				finding.ComputedEvidence("dkim.flags", "t=y")).
				WithDescription(selector+"."))
		}
	}

	return findings
}
