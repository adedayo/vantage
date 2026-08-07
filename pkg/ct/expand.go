package ct

import (
	"context"
	"sort"
)

// DefaultPivotDepth is how far co-tenancy is followed by default.
//
// One hop finds the sibling domains a group actually operates, which is the
// question an owner is asking: "what else of mine is out there?". Each further
// hop multiplies both the query cost and the chance of drifting onto somebody
// else's estate, because a single wrong inference at depth one becomes the
// starting point for depth two.
const DefaultPivotDepth = 1

// DefaultPivotBudget bounds how many domains an expansion will enumerate.
//
// Depth alone is not a bound: one certificate naming twenty siblings, each
// naming twenty more, is a large crawl at depth two. The budget is the
// backstop that makes the worst case knowable regardless of what the logs
// return.
const DefaultPivotBudget = 50

// PivotOptions configure an expansion.
type PivotOptions struct {
	// Depth is how many hops of co-tenancy to follow. Zero uses
	// DefaultPivotDepth. Negative disables pivoting, enumerating only the
	// domain given.
	Depth int
	// Budget caps how many domains are enumerated in total, including the
	// starting domain. Zero uses DefaultPivotBudget.
	Budget int
	// MaxSANsForRelation overrides how large a certificate may be before
	// co-tenancy stops implying common ownership. Zero uses
	// DefaultMaxSANsForRelation.
	//
	// This is the riskiest of the three to raise. Depth and budget bound how
	// far a correct inference travels; this one governs whether the inference
	// is sound at all, so raising it does not merely find more — it admits
	// domains that are related by nothing more than a shared host.
	MaxSANsForRelation int
}

// collectOptions projects the pivot bounds onto the collection bounds.
func (o PivotOptions) collectOptions() CollectOptions {
	return CollectOptions{MaxSANsForRelation: o.MaxSANsForRelation}
}

// Discovery is one domain's enumeration and how it was reached.
type Discovery struct {
	// Domain is the registrable domain enumerated.
	Domain string
	// Result is what its certificates revealed.
	Result Result
	// Depth is how many pivots from the starting domain this was, so the
	// starting domain is zero.
	Depth int
	// Via is the domain whose certificate named this one. It is empty for the
	// starting domain. Keeping it means a report can show why a domain was
	// implicated, which is the difference between evidence and assertion.
	Via string
}

// Expansion is the full result of a pivoting enumeration.
type Expansion struct {
	// Root is the domain the expansion started from.
	Root string
	// Discoveries are the domains enumerated, in breadth-first order, with the
	// root first.
	Discoveries []Discovery
	// BudgetExhausted reports that the walk stopped because the budget ran
	// out rather than because it had nothing left to follow. The caller must
	// be able to say the inventory is partial.
	BudgetExhausted bool
	// Errors records domains that could not be enumerated, keyed by domain.
	// A sibling that fails is not fatal: the rest of the estate is still
	// worth reporting, and a silent omission would be worse than a noted one.
	Errors map[string]error
}

// Domains returns every domain reached, root first then the rest in order.
func (e Expansion) Domains() []string {
	out := make([]string, 0, len(e.Discoveries))
	for _, d := range e.Discoveries {
		out = append(out, d.Domain)
	}
	return out
}

// RelatedDomains returns the domains discovered by pivoting, excluding the
// root.
func (e Expansion) RelatedDomains() []string {
	out := make([]string, 0, len(e.Discoveries))
	for _, d := range e.Discoveries {
		if d.Depth > 0 {
			out = append(out, d.Domain)
		}
	}
	sort.Strings(out)
	return out
}

// Hosts returns every hostname discovered across the whole expansion.
func (e Expansion) Hosts() []string {
	seen := map[string]bool{}
	for _, d := range e.Discoveries {
		for _, h := range d.Result.Hosts {
			seen[h] = true
		}
	}
	return sortedKeys(seen)
}

// Expand enumerates a domain and, where co-tenancy on a certificate suggests
// common ownership, the domains it shares certificates with.
//
// The walk is breadth-first so that the budget, when it binds, is spent on the
// domains closest to the starting point. Those are the ones most likely to be
// the operator's own: a depth-one sibling shares a certificate with the domain
// they named, whereas a depth-two domain is related only by inference upon
// inference.
//
// Every domain goes through Enumerate, so the existing per-domain cache
// applies. Re-running an expansion within the TTL costs no requests at all,
// which is what makes it reasonable to pivot on a public service.
func Expand(ctx context.Context, src Source, domain string, opts PivotOptions) (Expansion, error) {
	depth := opts.Depth
	if depth == 0 {
		depth = DefaultPivotDepth
	}
	budget := opts.Budget
	if budget <= 0 {
		budget = DefaultPivotBudget
	}

	root := RegistrableDomain(domain)
	if root == "" {
		// Fall back to the name as given: a target under a suffix the list
		// does not know is still worth enumerating on its own.
		root = normaliseName(domain)
	}

	exp := Expansion{Root: root, Errors: map[string]error{}}

	// The root is enumerated whatever happens, and its failure is the caller's
	// problem rather than a noted one: an expansion whose starting point could
	// not be reached has found nothing.
	rootResult, err := EnumerateWith(ctx, src, root, opts.collectOptions())
	if err != nil {
		return Expansion{}, err
	}
	exp.Discoveries = append(exp.Discoveries, Discovery{
		Domain: root, Result: rootResult, Depth: 0,
	})

	visited := map[string]bool{root: true}

	type pending struct {
		domain string
		depth  int
		via    string
	}

	var queue []pending
	enqueue := func(from Discovery) {
		if from.Depth >= depth {
			return
		}
		for _, rel := range from.Result.RelatedDomains {
			if rel == "" || visited[rel] {
				continue
			}
			// Marked visited on enqueue, not on processing, so that a domain
			// named by two siblings is queued once.
			visited[rel] = true
			queue = append(queue, pending{domain: rel, depth: from.Depth + 1, via: from.Domain})
		}
	}
	enqueue(exp.Discoveries[0])

	for len(queue) > 0 {
		if ctx.Err() != nil {
			return exp, ctx.Err()
		}
		if len(exp.Discoveries) >= budget {
			exp.BudgetExhausted = true
			break
		}

		next := queue[0]
		queue = queue[1:]

		res, err := EnumerateWith(ctx, src, next.domain, opts.collectOptions())
		if err != nil {
			exp.Errors[next.domain] = err
			continue
		}

		d := Discovery{Domain: next.domain, Result: res, Depth: next.depth, Via: next.via}
		exp.Discoveries = append(exp.Discoveries, d)
		enqueue(d)
	}

	return exp, nil
}
