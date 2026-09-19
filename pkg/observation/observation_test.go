package observation_test

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/adedayo/vantage/pkg/netattr"
	"github.com/adedayo/vantage/pkg/observation"
)

func provenance(provider, url string, fetched time.Time) netattr.SourceProvenance {
	return netattr.SourceProvenance{Provider: provider, URL: url, Fetched: fetched}
}

// A refresh changes the fetch time on every run by definition. Comparing on it
// would report drift every time, which destroys trust in the signal faster
// than missing drift does.
func TestSameBasisIgnoresFetchTime(t *testing.T) {
	monday := time.Date(2026, 9, 14, 6, 0, 0, 0, time.UTC)
	friday := monday.Add(4 * 24 * time.Hour)

	a := []netattr.SourceProvenance{provenance("aws", "https://example.test/aws.json", monday)}
	b := []netattr.SourceProvenance{provenance("aws", "https://example.test/aws.json", friday)}

	if !observation.SameBasis(a, b) {
		t.Fatal("provenance differing only in fetch time should compare equal")
	}
}

// A fallback endpoint can cover a different population, so an attribution
// drawn from one is not interchangeable with an attribution drawn from the
// other. That difference is material and must not be suppressed.
func TestSameBasisDetectsADifferentEndpoint(t *testing.T) {
	at := time.Date(2026, 9, 14, 6, 0, 0, 0, time.UTC)

	a := []netattr.SourceProvenance{provenance("aws", "https://preferred.test/aws.json", at)}
	b := []netattr.SourceProvenance{provenance("aws", "https://fallback.test/aws.json", at)}

	if observation.SameBasis(a, b) {
		t.Fatal("a different endpoint is a different basis and must not be suppressed")
	}
}

func TestSameBasisDetectsAnAddedOrRemovedSource(t *testing.T) {
	at := time.Date(2026, 9, 14, 6, 0, 0, 0, time.UTC)

	one := []netattr.SourceProvenance{provenance("aws", "https://example.test/aws.json", at)}
	two := append([]netattr.SourceProvenance{}, one...)
	two = append(two, provenance("gcp", "https://example.test/gcp.json", at))

	if observation.SameBasis(one, two) {
		t.Fatal("a source appearing or disappearing changes the basis")
	}
}

// Resolves and NXDOMAIN are not negations of each other. A query that failed
// leaves both false, and a discovery pipeline that reads that as "absent"
// drops real assets while one that reads it as "present" invents them.
func TestCTHostDistinguishesUndeterminedFromAbsent(t *testing.T) {
	for _, tc := range []struct {
		name             string
		host             observation.CTHost
		wantUndetermined bool
	}{
		{"resolves", observation.CTHost{Resolves: true}, false},
		{"confirmed absent", observation.CTHost{NXDOMAIN: true}, false},
		{"query failed", observation.CTHost{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.host.Undetermined(); got != tc.wantUndetermined {
				t.Fatalf("Undetermined() = %v, want %v", got, tc.wantUndetermined)
			}
		})
	}
}

func TestAgeReportsTheOldestEntry(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	p := []netattr.SourceProvenance{
		provenance("aws", "https://example.test/aws.json", now.Add(-2*time.Hour)),
		provenance("gcp", "https://example.test/gcp.json", now.Add(-30*time.Hour)),
	}

	age, ok := observation.Age(p, now)
	if !ok {
		t.Fatal("expected provenance to be present")
	}
	if age != 30*time.Hour {
		t.Fatalf("age = %v, want the oldest entry's age of 30h", age)
	}
}

// An absent provenance is not an age of zero. Zero would read as "fetched just
// now", which is the reassuring reading of "we do not know".
func TestAgeReportsAbsenceRatherThanZero(t *testing.T) {
	if _, ok := observation.Age(nil, time.Now()); ok {
		t.Fatal("absent provenance must report absence, not an age of zero")
	}
}

// The attribution must survive the JSON boundary intact: a consumer reading
// the serialised result is the case this whole package exists to serve.
func TestNetworkObservationRoundTripsThroughJSON(t *testing.T) {
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	original := observation.Network{
		Domain: "example.test",
		Hosts: []observation.NetworkHost{{
			Host: "example.test",
			Role: "apex",
			Attributions: []netattr.Attribution{{
				Address:      netip.MustParseAddr("203.0.113.7"),
				Provider:     "aws",
				Region:       "eu-west-1",
				Jurisdiction: "IE",
				Prefix:       prefix,
			}},
		}},
		FailedSources: []string{"gcp"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got observation.Network
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	a := got.Hosts[0].Attributions[0]
	if a.Provider != "aws" || a.Region != "eu-west-1" || a.Jurisdiction != "IE" {
		t.Fatalf("attribution did not survive the round trip: %+v", a)
	}
	if a.Prefix != prefix {
		t.Fatalf("prefix = %v, want %v", a.Prefix, prefix)
	}
	// A failed source must survive too: it is what stops an unattributed
	// address reading as "known to be in no provider range".
	if len(got.FailedSources) != 1 || got.FailedSources[0] != "gcp" {
		t.Fatalf("failed sources = %v, want [gcp]", got.FailedSources)
	}
}
