package audit

import (
	"context"
	"sort"
	"strconv"

	"github.com/adedayo/vantage/pkg/ct"
	"github.com/adedayo/vantage/pkg/finding"
)

// expandTargets follows certificate co-tenancy outwards and returns the
// original targets together with the domains discovered.
//
// Discovered domains are appended after the supplied ones rather than merged
// and sorted, so that a report leads with what the operator asked about. The
// pivot is a widening of the question, not a replacement for it.
//
// A pivot that fails is not fatal. The audit proceeds with the targets given,
// which is exactly what would have happened without the flag, and the failure
// is recorded so the operator knows the inventory may be narrower than asked
// for rather than concluding the estate is small.
func (r *Runner) expandTargets(ctx context.Context, result *finding.Result, targets []string) []string {
	// One cache and one source for the whole expansion, so that domains
	// reached from two different targets are fetched once.
	cache := NewCacheWithHTTP(r.Resolver, r.HTTP).WithRangeStore(r.RangeStore)
	src := sourceFor(cache)

	opts := ct.PivotOptions{
		Depth:              r.PivotDepth,
		Budget:             r.PivotBudget,
		MaxSANsForRelation: r.PivotMaxSANs,
	}

	seen := map[string]bool{}
	for _, t := range targets {
		seen[t] = true
	}

	var discovered []string

	for _, target := range targets {
		exp, err := ct.Expand(ctx, src, target, opts)
		if err != nil {
			result.AddError(finding.CheckError{
				Check:   "ct",
				Target:  target,
				Code:    finding.ErrCodeInternal,
				Message: "certificate pivot failed: " + err.Error(),
			})
			continue
		}

		var added []string
		for _, d := range exp.Discoveries {
			if d.Depth == 0 || seen[d.Domain] {
				continue
			}
			seen[d.Domain] = true
			discovered = append(discovered, d.Domain)
			added = append(added, d.Domain+" (via "+d.Via+")")
		}

		// Domains that could not be enumerated are still reported. A sibling
		// whose logs were unreachable is not a sibling that does not exist.
		for domain, enumErr := range exp.Errors {
			result.AddError(finding.CheckError{
				Check:   "ct",
				Target:  domain,
				Code:    finding.ErrCodeInternal,
				Message: "discovered via " + target + " but could not be enumerated: " + enumErr.Error(),
			})
		}

		if len(added) > 0 {
			sort.Strings(added)
			evidence := []finding.Evidence{
				finding.ComputedEvidence("ct.related.count", strconv.Itoa(len(added))),
			}
			for _, a := range added {
				evidence = append(evidence, finding.ComputedEvidence("ct.related.domain", a))
			}
			if exp.BudgetExhausted {
				evidence = append(evidence, finding.ComputedEvidence("ct.related.truncated",
					"the pivot budget was reached, so further related domains may exist"))
			}
			result.Add(finding.New("SURF-CT-004", target, evidence...))
		}
	}

	return append(targets, discovered...)
}
