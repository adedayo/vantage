package ct

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestExpandLive exercises the pivot against the real log services. It is
// skipped unless VANTAGE_LIVE_CT names a domain to expand, so ordinary runs
// stay hermetic and do not depend on a third party being reachable.
//
// Run it as: VANTAGE_LIVE_CT=example.com go test ./pkg/ct/ -run Live -v
func TestExpandLive(t *testing.T) {
	domain := os.Getenv("VANTAGE_LIVE_CT")
	if domain == "" {
		t.Skip("set VANTAGE_LIVE_CT=<domain> to run the live expansion test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	exp, err := Expand(ctx, CertSpotter(), domain, PivotOptions{})
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}

	t.Logf("root=%s domains=%d budgetExhausted=%v errors=%d",
		exp.Root, len(exp.Discoveries), exp.BudgetExhausted, len(exp.Errors))
	for _, d := range exp.Discoveries {
		t.Logf("  depth=%d %-28s hosts=%-4d related=%v via=%s",
			d.Depth, d.Domain, len(d.Result.Hosts), d.Result.RelatedDomains, d.Via)
	}
	t.Logf("related: %v", exp.RelatedDomains())
	t.Logf("total hosts: %d", len(exp.Hosts()))
}
