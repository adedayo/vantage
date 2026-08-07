package ct

import (
	"context"
	"errors"
	"strconv"
	"testing"
)

// fakeSource serves canned certificates per domain.
type fakeSource struct {
	name  string
	certs map[string][]Certificate
	fail  map[string]bool
	calls map[string]int
}

func newFakeSource() *fakeSource {
	return &fakeSource{
		name:  "fake",
		certs: map[string][]Certificate{},
		fail:  map[string]bool{},
		calls: map[string]int{},
	}
}

func (f *fakeSource) Name() string { return f.name }

// isolateCache points the on-disk CT cache at a temporary directory.
//
// Enumerate deliberately persists results, so without this a test would both
// read entries written by an earlier test and leave entries behind in the
// developer's real cache. Each test gets its own directory, and the source name
// is made unique so that nothing is shared even if a directory were reused.
func isolateCache(t *testing.T, f *fakeSource) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CACHE_HOME", dir)
	f.name = "fake-" + t.Name()
}

func (f *fakeSource) Search(_ context.Context, domain string) ([]Certificate, error) {
	f.calls[domain]++
	if f.fail[domain] {
		return nil, errors.New("source unavailable")
	}
	return f.certs[domain], nil
}

func TestCollectRelatedDomains(t *testing.T) {
	// A small certificate naming several domains is the co-tenancy signal the
	// pivot depends on.
	certs := []Certificate{{
		Names: []string{
			"glgroup.com", "*.glgroup.com",
			"glg.it", "*.glg.it",
			"glgresearch.com",
			"www.glgroup.com",
		},
	}}

	got := Collect("glgroup.com", certs)

	wantHosts := []string{"glgroup.com", "www.glgroup.com"}
	assertEqualSlices(t, "hosts", got.Hosts, wantHosts)
	assertEqualSlices(t, "wildcards", got.WildcardNames, []string{"*.glgroup.com"})
	assertEqualSlices(t, "related", got.RelatedDomains, []string{"glg.it", "glgresearch.com"})
}

func TestCollectRelatedExcludesSelfAndSubdomains(t *testing.T) {
	certs := []Certificate{{
		Names: []string{"a.glgroup.com", "b.glgroup.com", "other.com"},
	}}

	got := Collect("a.glgroup.com", certs)

	// b.glgroup.com is outside the searched zone but shares its registrable
	// domain, so it must not be offered as a pivot back onto ourselves.
	assertEqualSlices(t, "related", got.RelatedDomains, []string{"other.com"})
}

func TestCollectIgnoresRelationsOnLargeCertificates(t *testing.T) {
	// A bundling certificate: the target plus far too many unrelated names for
	// co-tenancy to imply anything. The in-domain name must still be kept.
	names := []string{"www.glgroup.com"}
	for i := 0; i < DefaultMaxSANsForRelation; i++ {
		names = append(names, "customer"+strconv.Itoa(i)+".example.net")
	}

	got := Collect("glgroup.com", []Certificate{{Names: names}})

	assertEqualSlices(t, "hosts", got.Hosts, []string{"www.glgroup.com"})
	if len(got.RelatedDomains) != 0 {
		t.Errorf("expected no related domains from a bundling certificate, got %v", got.RelatedDomains)
	}
}

func TestExpandFollowsCoTenancyToDepth(t *testing.T) {
	src := newFakeSource()
	isolateCache(t, src)
	src.certs["glgroup.com"] = []Certificate{{Names: []string{"glgroup.com", "glg.it"}}}
	src.certs["glg.it"] = []Certificate{{Names: []string{"glg.it", "glginsight.com"}}}
	src.certs["glginsight.com"] = []Certificate{{Names: []string{"glginsight.com"}}}

	t.Run("depth one stops after the first hop", func(t *testing.T) {
		exp, err := Expand(context.Background(), src, "glgroup.com", PivotOptions{Depth: 1})
		if err != nil {
			t.Fatalf("Expand: %v", err)
		}
		assertEqualSlices(t, "related", exp.RelatedDomains(), []string{"glg.it"})
	})

	t.Run("depth two follows the second hop", func(t *testing.T) {
		exp, err := Expand(context.Background(), src, "glgroup.com", PivotOptions{Depth: 2})
		if err != nil {
			t.Fatalf("Expand: %v", err)
		}
		assertEqualSlices(t, "related", exp.RelatedDomains(), []string{"glg.it", "glginsight.com"})
	})

	t.Run("negative depth disables pivoting", func(t *testing.T) {
		exp, err := Expand(context.Background(), src, "glgroup.com", PivotOptions{Depth: -1})
		if err != nil {
			t.Fatalf("Expand: %v", err)
		}
		if len(exp.RelatedDomains()) != 0 {
			t.Errorf("expected no pivoting, got %v", exp.RelatedDomains())
		}
	})
}

func TestExpandRespectsBudget(t *testing.T) {
	src := newFakeSource()
	isolateCache(t, src)
	related := []string{"glgroup.com"}
	for i := 0; i < 10; i++ {
		related = append(related, "sibling"+strconv.Itoa(i)+".com")
	}
	src.certs["glgroup.com"] = []Certificate{{Names: related}}

	exp, err := Expand(context.Background(), src, "glgroup.com", PivotOptions{Depth: 1, Budget: 4})
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}

	if len(exp.Discoveries) != 4 {
		t.Errorf("expected the budget to cap discoveries at 4, got %d", len(exp.Discoveries))
	}
	if !exp.BudgetExhausted {
		t.Error("expected BudgetExhausted to be set so the caller can say the result is partial")
	}
}

func TestExpandRecordsSiblingFailuresWithoutAborting(t *testing.T) {
	src := newFakeSource()
	isolateCache(t, src)
	src.certs["glgroup.com"] = []Certificate{{Names: []string{"glgroup.com", "glg.it", "good.com"}}}
	src.certs["good.com"] = []Certificate{{Names: []string{"good.com"}}}
	src.fail["glg.it"] = true

	exp, err := Expand(context.Background(), src, "glgroup.com", PivotOptions{Depth: 1})
	if err != nil {
		t.Fatalf("Expand must not fail because one sibling did: %v", err)
	}

	assertEqualSlices(t, "related", exp.RelatedDomains(), []string{"good.com"})
	if _, ok := exp.Errors["glg.it"]; !ok {
		t.Error("expected the failed sibling to be recorded rather than silently dropped")
	}
}

func TestExpandFailsWhenRootUnreachable(t *testing.T) {
	src := newFakeSource()
	isolateCache(t, src)
	src.fail["glgroup.com"] = true

	if _, err := Expand(context.Background(), src, "glgroup.com", PivotOptions{}); err == nil {
		t.Error("expected an error when the starting domain cannot be enumerated")
	}
}

func TestExpandVisitsEachDomainOnce(t *testing.T) {
	// Sibling certificates name each other, which would loop without the
	// visited set.
	src := newFakeSource()
	isolateCache(t, src)
	src.certs["glgroup.com"] = []Certificate{{Names: []string{"glgroup.com", "glg.it"}}}
	src.certs["glg.it"] = []Certificate{{Names: []string{"glg.it", "glgroup.com"}}}

	exp, err := Expand(context.Background(), src, "glgroup.com", PivotOptions{Depth: 3})
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}

	if len(exp.Discoveries) != 2 {
		t.Fatalf("expected 2 discoveries, got %d", len(exp.Discoveries))
	}
	for domain, n := range src.calls {
		if n != 1 {
			t.Errorf("domain %s was searched %d times, expected once", domain, n)
		}
	}
}

func TestExpansionRecordsHowEachDomainWasReached(t *testing.T) {
	src := newFakeSource()
	isolateCache(t, src)
	src.certs["glgroup.com"] = []Certificate{{Names: []string{"glgroup.com", "glg.it"}}}
	src.certs["glg.it"] = []Certificate{{Names: []string{"glg.it"}}}

	exp, err := Expand(context.Background(), src, "glgroup.com", PivotOptions{Depth: 1})
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}

	for _, d := range exp.Discoveries {
		switch d.Domain {
		case "glgroup.com":
			if d.Via != "" || d.Depth != 0 {
				t.Errorf("root should have no Via and depth 0, got via=%q depth=%d", d.Via, d.Depth)
			}
		case "glg.it":
			if d.Via != "glgroup.com" || d.Depth != 1 {
				t.Errorf("expected glg.it via glgroup.com at depth 1, got via=%q depth=%d", d.Via, d.Depth)
			}
		}
	}
}

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"www.glgroup.com": "glgroup.com",
		"glgroup.com":     "glgroup.com",
		"a.b.glg.it":      "glg.it",
		"example.co.uk":   "example.co.uk",
		"a.example.co.uk": "example.co.uk",
		"WWW.GLGROUP.COM": "glgroup.com",
		"com":             "",
		"":                "",
	}
	for in, want := range cases {
		if got := RegistrableDomain(in); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCollectWithConfigurableCeiling(t *testing.T) {
	// A certificate just above the default ceiling: ignored by default,
	// admitted when the operator raises the bound.
	names := []string{"www.glgroup.com"}
	for i := 0; i < DefaultMaxSANsForRelation; i++ {
		names = append(names, "sibling"+strconv.Itoa(i)+".example.net")
	}
	certs := []Certificate{{Names: names}}

	if got := CollectWith("glgroup.com", certs, CollectOptions{}); len(got.RelatedDomains) != 0 {
		t.Errorf("default ceiling should reject this certificate, got %v", got.RelatedDomains)
	}

	raised := CollectWith("glgroup.com", certs, CollectOptions{MaxSANsForRelation: 100})
	if len(raised.RelatedDomains) == 0 {
		t.Error("raising the ceiling should admit the certificate")
	}

	// Lowering below the certificate size must exclude it again, so the knob
	// works in both directions rather than only ever widening.
	lowered := CollectWith("glgroup.com", certs, CollectOptions{MaxSANsForRelation: 2})
	if len(lowered.RelatedDomains) != 0 {
		t.Errorf("lowering the ceiling should reject the certificate, got %v", lowered.RelatedDomains)
	}
}

func TestExpandHonoursMaxSANsOption(t *testing.T) {
	src := newFakeSource()
	isolateCache(t, src)

	names := []string{"glgroup.com"}
	for i := 0; i < 40; i++ {
		names = append(names, "neighbour"+strconv.Itoa(i)+".example.net")
	}
	src.certs["glgroup.com"] = []Certificate{{Names: names}}

	// The default ceiling treats a 41-name certificate as shared hosting.
	exp, err := Expand(context.Background(), src, "glgroup.com", PivotOptions{Depth: 1})
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if len(exp.RelatedDomains()) != 0 {
		t.Errorf("expected no pivot at the default ceiling, got %v", exp.RelatedDomains())
	}

	// Raising it past the certificate size makes the pivot follow them, which
	// is exactly the behaviour an operator opts into when they widen the knob.
	wide, err := Expand(context.Background(), src, "glgroup.com",
		PivotOptions{Depth: 1, Budget: 5, MaxSANsForRelation: 100})
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if len(wide.RelatedDomains()) == 0 {
		t.Error("expected the raised ceiling to admit related domains")
	}
}

func assertEqualSlices(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %v, want %v", label, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s: got %v, want %v", label, got, want)
		}
	}
}
