package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	d "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/analyse"
)

// maxPolicySize bounds how much of the policy file is read.
//
// A policy is a few hundred bytes; anything larger is a misconfiguration or a
// deliberate attempt to make the auditor consume memory on a response it asked
// for. Reading a bounded prefix is enough to parse or to reject it.
const maxPolicySize = 64 * 1024

// FetchMTASTSPolicy retrieves the MTA-STS policy file for a domain.
//
// The request follows RFC 8461 §3.3 strictly: HTTPS only, at the well-known
// path, on the mta-sts host, with no redirects. Redirects are refused rather
// than followed because a sender must not accept a policy from a location the
// domain owner did not publish — following one would let anyone who can
// intercept the request substitute their own policy.
//
// A failure to retrieve or validate is reported in the returned policy rather
// than as an error, because "the policy is unreachable" is a finding about the
// domain, not a failure of the tool.
func FetchMTASTSPolicy(ctx context.Context, r d.Resolver, hc d.Doer, domain string) analyse.MTASTSPolicy {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	url := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"

	// The resolver's own budget is used when it exposes one, so that a caller
	// who slowed DNS down for a lossy link gets the same patience here.
	//
	// The assertion is checked. Resolver does not require TotalTimeout, and an
	// embedding consumer's wrapper — a scope guard, say — has no reason to
	// forward it; asserting unconditionally would panic on exactly the
	// implementations this library exists to accept.
	timeout := d.DefaultTotalTimeout
	if budgeted, ok := r.(interface{ TotalTimeout() time.Duration }); ok {
		timeout = budgeted.TotalTimeout()
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return analyse.MTASTSPolicy{
			Fetched: true, CertificateValid: true,
			Reason: "the time budget was exhausted before the policy could be fetched",
		}
	}

	client := d.HTTPOr(hc, d.HTTPOptions{Timeout: timeout})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return analyse.MTASTSPolicy{
			Fetched: true, CertificateValid: true,
			Reason: "the policy URL could not be constructed",
		}
	}
	req.Header.Set("User-Agent", "vantage")

	resp, err := client.Do(req)
	if err != nil {
		// A certificate failure is a distinct, more actionable diagnosis than
		// general unreachability, so it is separated here rather than folded
		// into a single "could not fetch".
		if isCertificateError(err) {
			return analyse.MTASTSPolicy{Fetched: true, CertificateValid: false,
				Reason: "the policy host's certificate did not validate"}
		}
		return analyse.MTASTSPolicy{Fetched: true, CertificateValid: true,
			Reason: fmt.Sprintf("the policy could not be retrieved: %v", err)}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return analyse.MTASTSPolicy{Fetched: true, CertificateValid: true,
			Reason: "the policy URL redirected, which RFC 8461 does not permit"}
	}
	if resp.StatusCode != http.StatusOK {
		return analyse.MTASTSPolicy{Fetched: true, CertificateValid: true,
			Reason: fmt.Sprintf("the policy URL returned HTTP %d", resp.StatusCode)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicySize))
	if err != nil {
		return analyse.MTASTSPolicy{Fetched: true, CertificateValid: true,
			Reason: "the policy body could not be read"}
	}

	policy := analyse.ParseMTASTSPolicy(string(body))
	policy.CertificateValid = true
	return policy
}

// isCertificateError reports whether a transport error was caused by TLS
// verification failing, as opposed to the host being unreachable.
func isCertificateError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var recordErr *tls.CertificateVerificationError

	return errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostname) ||
		errors.As(err, &invalid) ||
		errors.As(err, &recordErr)
}
