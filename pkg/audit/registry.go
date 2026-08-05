package audit

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/adedayo/vantage/pkg/finding"
)

// Network describes the egress a check requires. Declaring it lets --no-network
// exclude checks honestly rather than having them fail at run time, and lets an
// automated caller understand the tool's blast radius before invoking it.
type Network string

const (
	// NetworkDNS means the check issues DNS queries only.
	NetworkDNS Network = "dns"
	// NetworkHTTPS means the check also makes HTTPS requests to the target.
	NetworkHTTPS Network = "https"
	// NetworkThirdParty means the check contacts a service other than the
	// target, such as a Certificate Transparency log.
	NetworkThirdParty Network = "third-party"
	// NetworkNone means the check needs no network at all.
	NetworkNone Network = "none"
)

// Description is a check's self-declaration, used for help text, profile
// membership and the forthcoming capability manifest.
type Description struct {
	// Name is the stable check identifier, e.g. "spf".
	Name string
	// Summary is a one-line explanation of what the check assesses.
	Summary string
	// Egress declares, as structured data, everything the check touches.
	// Network is derived from it, so the coarse classification and the
	// detailed one cannot disagree.
	Egress EgressProfile
	// DegradesWithoutNetwork declares that the check still yields useful
	// results with DNS alone, so --no-network should narrow it rather than
	// exclude it. MTA-STS is the motivating case: the policy file needs
	// HTTPS, but "no policy published at all" is the most common and most
	// serious finding and is visible from the TXT record alone. Dropping the
	// whole check would report silence as safety.
	DegradesWithoutNetwork bool
	// Findings lists the catalogue IDs the check can raise.
	Findings []string
	// TypicalQueries estimates the DNS queries a single run costs, so callers
	// can budget before invoking.
	TypicalQueries int
}

// Target is what a check assesses.
type Target struct {
	// Domain is the name under assessment.
	Domain string
	// Cache memoises DNS answers for the duration of a run, so that checks
	// needing the same record do not each pay for it.
	Cache *Cache
	// Hosts are additional names under the domain to assess, supplied by the
	// caller. Checks that examine individual hosts — subdomain takeover — use
	// them; the rest ignore them. Nothing is ever guessed to fill this list.
	Hosts []string
	// ExpectJurisdictions are the ISO 3166-1 alpha-2 countries the operator
	// declares their infrastructure should be in. Empty means no expectation
	// was stated, and the jurisdiction rule is then not evaluated: this tool
	// has no basis for guessing where an organisation intends to be hosted.
	ExpectJurisdictions []string
	// NoNetwork disables checks requiring egress beyond DNS.
	NoNetwork bool
}

// Outcome is what a check reports back.
type Outcome struct {
	// State records whether the assessed record was present, absent, skipped
	// or unassessable. Keeping these distinct is what stops a consumer
	// concluding a control is missing when it was simply never checked.
	State finding.State
	// Records holds the raw record data, preserving the retrieval behaviour of
	// the single-purpose commands.
	Records []string
	// Findings are the assessed issues.
	Findings []finding.Finding
}

// Check is the contract every assessment implements.
type Check interface {
	Describe() Description
	Run(ctx context.Context, t Target) (Outcome, error)
}

// CheckFunc adapts a plain function to the Check interface.
type CheckFunc struct {
	Description Description
	Fn          func(ctx context.Context, t Target) (Outcome, error)
}

// Describe implements Check.
func (c CheckFunc) Describe() Description { return c.Description }

// Run implements Check.
func (c CheckFunc) Run(ctx context.Context, t Target) (Outcome, error) { return c.Fn(ctx, t) }

var (
	registryMu sync.RWMutex
	registry   = map[string]Check{}
)

// Register adds a check to the registry. It panics on a duplicate or malformed
// registration, because both are programming errors that must fail loudly in
// tests rather than silently shadow a check at run time.
func Register(c Check) {
	desc := c.Describe()
	if strings.TrimSpace(desc.Name) == "" {
		panic("audit: check registered without a name")
	}

	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[desc.Name]; dup {
		panic(fmt.Sprintf("audit: duplicate check %q", desc.Name))
	}
	registry[desc.Name] = c
}

// Lookup returns a registered check by name.
func Lookup(name string) (Check, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	c, ok := registry[name]
	return c, ok
}

// Registered returns every registered check, ordered by name.
func Registered() []Check {
	registryMu.RLock()
	defer registryMu.RUnlock()

	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)

	checks := make([]Check, 0, len(names))
	for _, name := range names {
		checks = append(checks, registry[name])
	}
	return checks
}

// Names returns the sorted names of every registered check.
func Names() []string {
	names := make([]string, 0)
	for _, c := range Registered() {
		names = append(names, c.Describe().Name)
	}
	return names
}

// Descriptions returns every registered check's self-declaration.
func Descriptions() []Description {
	descs := make([]Description, 0)
	for _, c := range Registered() {
		descs = append(descs, c.Describe())
	}
	return descs
}

// Network returns the coarse egress classification, derived from the profile.
func (d Description) Network() []Network { return d.Egress.Networks() }

// RequiresNetwork reports whether a description needs egress beyond DNS.
func (d Description) RequiresNetwork() bool {
	return d.Egress.RequiresNetwork()
}

// ExcludedByNoNetwork reports whether --no-network should drop the check
// entirely. A check that declares it degrades is kept, because it detects the
// absence of a control from DNS alone; only checks that would produce nothing
// without egress are dropped.
func (d Description) ExcludedByNoNetwork() bool {
	return d.RequiresNetwork() && !d.DegradesWithoutNetwork
}

// ValidateRegistry checks that every registered check is coherent: it must have
// a summary, declare its egress, and reference only catalogue IDs that exist.
//
// The last of these is the important one. A check that raises a finding ID with
// no catalogue entry would produce a result nobody can act on, and would panic
// at run time; asserting it here means the failure surfaces in the test suite.
func ValidateRegistry() error {
	for _, desc := range Descriptions() {
		if strings.TrimSpace(desc.Summary) == "" {
			return fmt.Errorf("error: check %q has no summary", desc.Name)
		}
		if err := desc.Egress.validate(desc.Name); err != nil {
			return err
		}
		for _, id := range desc.Findings {
			if _, ok := finding.Lookup(id); !ok {
				return fmt.Errorf("error: check %q declares unknown finding %q", desc.Name, id)
			}
		}
	}
	return nil
}
