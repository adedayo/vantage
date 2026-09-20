package analyse

import (
	"context"
	"strconv"
	"strings"

	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/observation"
)

// SPFResolver supplies the lookups that recursive SPF evaluation needs.
//
// It is an interface rather than a direct dependency on the scanner so that
// the evaluation logic — the part that is easy to get subtly wrong — stays
// testable without a resolver, and so the audit runner can supply its per-run
// cache and pay for each name only once.
type SPFResolver interface {
	// TXT returns the TXT records published at name. It returns an empty slice
	// and no error when the name resolves but has no TXT records; an error
	// means the lookup itself did not complete.
	TXT(ctx context.Context, name string) ([]string, error)
	// HasRecords reports whether name has records of the kind a mechanism
	// requires: "a" for A/AAAA, "mx" for MX, "ptr" for PTR, "exists" for A.
	// It is used only to count void lookups, so a failed lookup should report
	// false rather than an error where the distinction does not matter.
	HasRecords(ctx context.Context, name, kind string) (bool, error)
}

// Evaluation limits. RFC 7208 §4.6.4 sets the first two; the third is ours.
const (
	// spfLookupLimit is the number of DNS-querying mechanisms RFC 7208 allows.
	spfLookupLimit = 10
	// spfVoidLimit is the number of lookups returning nothing that RFC 7208
	// allows before receivers may return PermError.
	spfVoidLimit = 2
	// spfMaxLookups bounds the work done once the limit is already exceeded.
	// The exact count of a pathological record is not worth unbounded queries
	// against someone else's nameservers; knowing it is "more than 10" is what
	// the operator has to act on.
	spfMaxLookups = 30
	// spfMaxDepth bounds include nesting, as a second guard alongside the
	// visited set. It sits deliberately above spfLookupLimit: a chain of
	// eleven includes is precisely the case worth diagnosing, and capping
	// depth at ten would truncate the walk just short of proving it, reporting
	// "at least 10" for a record we could have counted exactly. The real
	// bound on work is spfMaxLookups; this only stops runaway nesting.
	spfMaxDepth = spfMaxLookups
)

// SPFEvaluation is the result of recursively evaluating a record.
type SPFEvaluation struct {
	// Lookups counts the DNS-querying mechanisms encountered.
	Lookups int
	// VoidLookups counts lookups that returned no records.
	VoidLookups int
	// VoidNames lists the names that returned nothing, as evidence.
	VoidNames []string
	// BrokenTerms lists include/redirect terms whose target publishes no
	// usable SPF record.
	BrokenTerms []string
	// Loop is set when a domain includes itself, directly or transitively.
	Loop bool
	// LoopAt names the domain at which the cycle was detected.
	LoopAt string
	// Bounded is set when evaluation stopped at spfMaxLookups or spfMaxDepth
	// rather than completing, so Lookups is a lower bound.
	Bounded bool
}

// EvaluateSPF walks a record's include, redirect, a, mx, ptr and exists terms,
// counting lookups as RFC 7208 §4.6.4 requires.
//
// Evaluation is bounded in depth and by a visited set, so a record that
// includes itself produces a finding rather than a hang. The context bounds it
// in time; a cancelled context stops the walk and marks the result bounded.
func EvaluateSPF(ctx context.Context, r SPFResolver, domain, record string) SPFEvaluation {
	e := &SPFEvaluation{}
	visited := map[string]bool{normaliseDomain(domain): true}
	e.walk(ctx, r, domain, record, visited, 0)
	return *e
}

// walk evaluates one record, recursing into include and redirect targets.
func (e *SPFEvaluation) walk(ctx context.Context, r SPFResolver, domain, record string, visited map[string]bool, depth int) {
	if depth > spfMaxDepth {
		e.Bounded = true
		return
	}

	for _, term := range strings.Fields(record) {
		if ctx.Err() != nil || e.Lookups >= spfMaxLookups {
			e.Bounded = true
			return
		}

		bare := strings.ToLower(strings.TrimLeft(term, "+-~?"))
		name, value, hasValue := strings.Cut(bare, ":")
		if !hasValue {
			name, value, _ = strings.Cut(bare, "=")
		}

		switch name {
		case "include", "redirect":
			e.Lookups++
			e.follow(ctx, r, term, value, visited, depth)

		case "a", "mx", "ptr", "exists":
			e.Lookups++
			target := value
			if target == "" {
				target = domain
			}
			// A macro-expanded target cannot be resolved without the message
			// being evaluated, so it is counted but not probed. Guessing would
			// manufacture a void lookup that receivers would never see.
			if strings.Contains(target, "%") {
				continue
			}
			kind := name
			if kind == "exists" {
				kind = "a"
			}
			if ok, err := r.HasRecords(ctx, stripMask(target), kind); err == nil && !ok {
				e.void(stripMask(target))
			}
		}
	}
}

// follow recurses into an include or redirect target.
func (e *SPFEvaluation) follow(ctx context.Context, r SPFResolver, term, target string, visited map[string]bool, depth int) {
	target = strings.TrimSuffix(strings.TrimSpace(target), ".")
	if target == "" || strings.Contains(target, "%") {
		return
	}

	key := normaliseDomain(target)
	if visited[key] {
		// A cycle would otherwise recurse until the depth bound, reporting a
		// meaningless lookup count. Naming the domain tells the operator
		// exactly which term to cut.
		e.Loop, e.LoopAt = true, target
		return
	}
	visited[key] = true

	txts, err := r.TXT(ctx, target)
	if err != nil {
		e.void(target)
		e.addBroken(term)
		return
	}

	var records []string
	for _, txt := range txts {
		if txt = strings.TrimSpace(txt); strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			records = append(records, txt)
		}
	}
	if len(records) == 0 {
		// The name may resolve perfectly well and simply publish no SPF; that
		// is still a PermError for the including domain.
		if len(txts) == 0 {
			e.void(target)
		}
		e.addBroken(term)
		return
	}

	e.walk(ctx, r, target, records[0], visited, depth+1)
}

func (e *SPFEvaluation) void(name string) {
	e.VoidLookups++
	for _, seen := range e.VoidNames {
		if seen == name {
			return
		}
	}
	e.VoidNames = append(e.VoidNames, name)
}

func (e *SPFEvaluation) addBroken(term string) {
	for _, seen := range e.BrokenTerms {
		if seen == term {
			return
		}
	}
	e.BrokenTerms = append(e.BrokenTerms, term)
}

// stripMask removes a CIDR suffix from an a/mx mechanism target.
func stripMask(target string) string {
	if i := strings.IndexByte(target, '/'); i >= 0 {
		return target[:i]
	}
	return target
}

func normaliseDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
}

// SPFRecursive evaluates a domain's SPF records, including the rules that need
// further DNS lookups: the ten-lookup and void-lookup limits, unusable include
// targets, include loops and record length.
//
// It is a superset of SPF: the record-only rules are applied first, so callers
// with a resolver to hand should use this and callers without should use SPF.
func SPFRecursive(ctx context.Context, o Origin, r SPFResolver, records []string, hasMail bool) []finding.Finding {
	findings, _ := SPFObserved(ctx, o, r, records, hasMail)
	return findings
}

// SPFObserved is SPFRecursive, additionally returning the facts it established
// as structured data.
//
// It exists because a consumer computing its own severity needs the
// terminating mechanism and the lookup count, and the alternative — parsing
// them back out of rendered findings — would mean a second parser that can
// disagree with this one about what a record says. The evaluation is shared
// rather than repeated, so the observation costs no additional queries.
func SPFObserved(ctx context.Context, o Origin, r SPFResolver, records []string, hasMail bool) ([]finding.Finding, observation.SPF) {
	findings := SPF(o, records, hasMail)

	obs := observation.SPF{
		Presence:  observation.PresenceAbsent,
		SendsMail: hasMail,
	}
	if len(records) > 0 {
		obs.Presence = observation.PresencePublished
		obs.Record = records[0]
		obs.AllMechanism = strings.TrimSuffix(terminal(records[0]), "all")
		// A record that parsed well enough to yield terms is syntactically
		// usable; the specific defects are reported as findings rather than
		// by withholding this flag.
		obs.Valid = strings.HasPrefix(strings.ToLower(strings.TrimSpace(records[0])), "v=spf1")
	}

	if len(records) == 0 || r == nil {
		return findings, obs
	}

	record := records[0]
	ev := o.txtEvidence(o.Target, record)

	if lengths := lengthProblems(records); len(lengths) > 0 {
		findings = append(findings, finding.New("SURF-SPF-010", o.Target, ev,
			finding.ComputedEvidence("spf.length", strings.Join(lengths, "; "))))
	}

	eval := EvaluateSPF(ctx, r, o.Target, record)

	obs.Lookups = eval.Lookups
	obs.LookupLimitExceeded = eval.Lookups > spfLookupLimit

	count := strconv.Itoa(eval.Lookups)
	if eval.Bounded {
		count = "at least " + count
	}

	if eval.Lookups > spfLookupLimit {
		findings = append(findings, finding.New("SURF-SPF-006", o.Target, ev,
			finding.ComputedEvidence("spf.lookup_count", count),
			finding.ComputedEvidence("spf.lookup_limit", strconv.Itoa(spfLookupLimit))))
	}

	if eval.VoidLookups > spfVoidLimit {
		findings = append(findings, finding.New("SURF-SPF-007", o.Target, ev,
			finding.ComputedEvidence("spf.void_lookups", strconv.Itoa(eval.VoidLookups)),
			finding.ComputedEvidence("spf.void_names", strings.Join(eval.VoidNames, ", "))))
	}

	for _, term := range eval.BrokenTerms {
		findings = append(findings, finding.New("SURF-SPF-009", o.Target, ev,
			finding.ComputedEvidence("spf.term", term)))
	}

	if eval.Loop {
		// A loop is reported as an unusable term rather than a separate rule:
		// the operator's action is the same, and the evidence names the domain.
		findings = append(findings, finding.New("SURF-SPF-009", o.Target, ev,
			finding.ComputedEvidence("spf.include_loop", eval.LoopAt)).
			WithDescription("Specifically, evaluation revisits `"+eval.LoopAt+
				"`, so the include graph contains a cycle."))
	}

	return findings, obs
}

// lengthProblems reports records that breach the TXT string or total size
// guidance of RFC 7208 §3.3.
func lengthProblems(records []string) []string {
	var problems []string
	for _, record := range records {
		if len(record) > 512 {
			problems = append(problems,
				"record is "+strconv.Itoa(len(record))+" octets (over 512)")
			continue
		}
		// A record published as a single unsplit string longer than 255 octets
		// is invalid DNS; most interfaces split it, but not all do so safely.
		if len(record) > 255 && !strings.Contains(record, "\" \"") {
			problems = append(problems,
				"single string is "+strconv.Itoa(len(record))+" octets (over 255)")
		}
	}
	return problems
}
