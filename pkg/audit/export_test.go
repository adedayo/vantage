package audit

import (
	"context"

	d "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/ct"
	"github.com/adedayo/vantage/pkg/scanner"
)

// SetCorroborator replaces the takeover HTTP corroboration function for the
// duration of a test and returns a function restoring it.
//
// This lives in a _test.go file so the seam exists only in test builds: the
// production binary keeps the real implementation with no way to substitute it.
// The alternative — a name under the audited domain resolving to a server the
// test controls — cannot be arranged without either real DNS or a resolver
// override that would test the mock rather than the wiring.
func SetCorroborator(fn func(ctx context.Context, hc d.Doer, host string, fingerprints []string) scanner.TakeoverCorroboration) func() {
	previous := corroborate
	corroborate = fn
	return func() { corroborate = previous }
}

// SetCTSource replaces the Certificate Transparency source for the duration of
// a test and returns a function restoring it.
//
// Tests must never query the real crt.sh: it is a free public service, its
// contents change, and a test that depends on either would be both rude and
// unreliable.
func SetCTSource(src ct.Source) func() {
	previous := ctSource
	ctSource = src
	return func() { ctSource = previous }
}
