package netattr

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	d "github.com/adedayo/vantage/pkg"
)

// RangeStore is a durable cache of downloaded provider range files.
//
// It is an interface so that an embedding consumer can back it with its own
// storage and share one download across many assessments. Without it, each
// assessment would re-fetch several megabytes from four operators, which is
// precisely the inconsiderate behaviour this tool must avoid.
//
// Implementations must be safe for concurrent use.
type RangeStore interface {
	// Get returns cached content and when it was obtained. The boolean
	// reports whether anything was found, regardless of age: freshness is the
	// loader's judgement, because only it knows whether a stale entry is
	// preferable to no answer at all.
	Get(ctx context.Context, url string) (data []byte, at time.Time, ok bool)
	// Put records content obtained now.
	Put(ctx context.Context, url string, data []byte, at time.Time) error
}

// Loader fetches and memoises provider ranges.
//
// It replaces what used to be package-level state. The distinction matters for
// more than tidiness: the memo is populated by fetches made through a specific
// HTTP client, and an embedding consumer may have granted that client access to
// third-party endpoints under one authorisation and not another. A process-wide
// memo would let one assessment serve another the results of an endpoint the
// second was never permitted to contact — a consent leak that no scope guard
// downstream could detect, because no request would be made.
type Loader struct {
	// HTTP is the egress range files are fetched through. Nil uses the
	// library default client.
	HTTP d.Doer
	// Store, when non-nil, persists downloads between runs.
	Store RangeStore
	// TTL overrides how long a cached file is reused. Zero uses CacheTTL.
	TTL time.Duration

	mu     sync.Mutex
	cached *Set
}

// NewLoader builds a loader over an HTTP client and an optional store.
func NewLoader(hc d.Doer, store RangeStore) *Loader {
	return &Loader{HTTP: hc, Store: store}
}

// ttl reports the freshness window in force.
func (l *Loader) ttl() time.Duration {
	if l != nil && l.TTL > 0 {
		return l.TTL
	}
	return CacheTTL
}

// Load returns the provider ranges, fetching and caching them as needed.
//
// The result is memoised on the loader, so a portfolio audit of a hundred
// domains pays for the download once while two assessments under different
// authorisations remain independent.
func (l *Loader) Load(ctx context.Context) (Set, error) {
	if l == nil {
		return Set{}, fmt.Errorf("error: no provider range loader configured")
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cached != nil {
		return *l.cached, nil
	}

	set := Set{Fetched: time.Now().UTC()}
	byName := map[string]*Provider{}

	for _, src := range providerSources {
		ranges, used, at, failures := src.load(ctx, l)
		if ranges == nil {
			set.Failed = append(set.Failed,
				src.name+" ("+strings.Join(failures, "; ")+")")
			continue
		}
		// A cache entry older than the TTL means the operator's endpoint could
		// not be reached and older data is standing in for it. Disclosing the
		// age is what keeps stale-on-unreachable defensible.
		if time.Since(at) > l.ttl() {
			set.Stale = append(set.Stale, fmt.Sprintf("%s (%s, cached %s)",
				src.name, used, at.Format(time.RFC3339)))
		}
		set.Provenance = append(set.Provenance, SourceProvenance{
			Provider: src.name, URL: used, Fetched: at.UTC(),
		})

		p, ok := byName[src.name]
		if !ok {
			p = &Provider{Name: src.name, Source: used}
			byName[src.name] = p
		}
		p.Ranges = append(p.Ranges, ranges...)
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		set.Providers = append(set.Providers, *byName[name])
	}

	if len(set.Providers) == 0 {
		return set, fmt.Errorf("error: no cloud provider ranges could be retrieved (%s)",
			strings.Join(set.Failed, "; "))
	}

	l.cached = &set
	return set, nil
}

// Reset clears the loader's memo. Tests use it; nothing else should.
func (l *Loader) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cached = nil
}
