package observation

// Presence is whether a DNS-published control was found, and is deliberately
// three-valued.
//
// The distinction the third value protects is the one a reader most needs and
// is least able to reconstruct: a control that is absent is a decision somebody
// made, and a control we could not look for is a gap in our own evidence. Both
// render as "no record" if they are collapsed into a boolean, and the collapse
// is invisible at the point of reading — which is the direction that gets
// someone into trouble, because an outage then presents as a clean bill of
// health.
type Presence string

const (
	// PresencePublished means the record was retrieved.
	PresencePublished Presence = "published"
	// PresenceAbsent means the resolver answered definitively that no such
	// record exists. It is a finding about the domain.
	PresenceAbsent Presence = "absent"
	// PresenceUndetermined means the lookup did not complete, or completed
	// without settling the question. It is a finding about the assessment.
	PresenceUndetermined Presence = "undetermined"
)

// Settled reports whether the lookup answered the question either way.
func (p Presence) Settled() bool {
	return p == PresencePublished || p == PresenceAbsent
}

// SPF is the sender authorisation a domain publishes.
type SPF struct {
	// Presence is whether an SPF record was retrieved.
	Presence Presence `json:"presence"`
	// Record is the raw policy, kept so a reader can see what was judged.
	Record string `json:"record,omitempty"`
	// AllMechanism is the qualifier on the terminating all-mechanism: "+",
	// "~", "-", "?", or empty when the record does not terminate in one.
	//
	// "+all" authorises the entire internet to send as the domain, which is
	// materially worse than publishing nothing, because it converts a receiver
	// check that would have been inconclusive into one that passes.
	AllMechanism string `json:"all_mechanism,omitempty"`
	// Valid reports whether the record parsed as RFC 7208 syntax.
	Valid bool `json:"valid"`
	// Lookups is the number of DNS-querying mechanisms the record expands to.
	// Above ten, receivers are entitled to stop evaluating and return permerror
	// — so a domain can publish a perfectly reasonable policy that is not
	// enforced anywhere.
	Lookups int `json:"lookups"`
	// LookupLimitExceeded reports that the ten-lookup limit was passed.
	LookupLimitExceeded bool `json:"lookup_limit_exceeded,omitempty"`
	// SendsMail reports whether the domain publishes mail exchangers. A domain
	// that sends no mail needs a different policy from one that does, and
	// judging both by the same rule produces advice nobody can act on.
	SendsMail bool `json:"sends_mail"`
}

// DKIM is what probing selectors established, and — as importantly — what it
// did not.
type DKIM struct {
	// SelectorsExamined are the selectors queried, in the order tried.
	SelectorsExamined []string `json:"selectors_examined,omitempty"`
	// SelectorsFound are those that returned a key record.
	SelectorsFound []string `json:"selectors_found,omitempty"`
	// UsableKeys counts keys that parsed, are not revoked and are not in test
	// mode.
	UsableKeys int `json:"usable_keys"`
	// Probed reports that the selectors were guessed from a list rather than
	// supplied by the operator.
	//
	// This is the field that decides what an absence means. Selectors are not
	// enumerable from DNS: a domain may sign every message with a selector
	// nobody can guess. When probing finds nothing, the only honest statement
	// is "none of the selectors we tried resolved" — never "this domain has no
	// DKIM", which is a claim the evidence cannot support.
	Probed bool `json:"probed"`
}

// Conclusive reports whether an absence of keys may be stated as a fact about
// the domain rather than about the search.
//
// It is false exactly when nothing was found by probing. An operator who names
// their own selectors gets a conclusive answer; a caller relying on the common
// list does not, and must say so.
func (d DKIM) Conclusive() bool {
	return d.UsableKeys > 0 || !d.Probed
}

// DMARC is the policy tags a deterministic severity must be a function of.
//
// They are carried as parsed values rather than as a raw record because a
// consumer computing priority from prose has to re-implement the parser, and
// will do it differently — so two parts of one system would disagree about
// what a domain's policy is.
type DMARC struct {
	// Presence is whether a DMARC record was retrieved.
	Presence Presence `json:"presence"`
	// Record is the raw policy.
	Record string `json:"record,omitempty"`
	// Policy is the p= tag: "none", "quarantine" or "reject".
	Policy string `json:"policy,omitempty"`
	// SubdomainPolicy is the sp= tag, empty when not stated. When it is weaker
	// than p=, every subdomain is a spoofing route the apex policy implies is
	// closed.
	SubdomainPolicy string `json:"subdomain_policy,omitempty"`
	// Percent is the pct= tag, defaulting to 100 as the RFC specifies. A
	// reject policy at pct=20 enforces against a fifth of spoofed mail.
	Percent int `json:"percent"`
	// AlignmentSPF and AlignmentDKIM are the aspf= and adkim= tags: "s" for
	// strict, "r" for relaxed.
	AlignmentSPF  string `json:"alignment_spf,omitempty"`
	AlignmentDKIM string `json:"alignment_dkim,omitempty"`
	// AggregateReporting reports whether a rua= destination is published.
	// Without one, the domain owner sees nothing, so a p=none policy is not
	// even serving its stated purpose of observation before enforcement.
	AggregateReporting bool `json:"aggregate_reporting"`
	// RecordCount is how many DMARC records were published. More than one is
	// an error: receivers are required to ignore all of them, so the domain is
	// unprotected while appearing configured.
	RecordCount int `json:"record_count"`
	// Valid reports whether the record parsed.
	Valid bool `json:"valid"`
}

// Enforcing reports whether the policy instructs receivers to act on
// unauthenticated mail across all of it.
//
// Both conditions are required. A reject policy at less than full percentage
// is partial enforcement, and reporting it as enforcement would tell a reader
// that a route is closed when it is open a measurable fraction of the time.
func (d DMARC) Enforcing() bool {
	return (d.Policy == "reject" || d.Policy == "quarantine") && d.Percent >= 100
}

// AdjacentRecord is one of the records surrounding the core three: MTA-STS,
// TLS-RPT, BIMI, CAA.
//
// They share a shape because they share a role: their absence is worth
// surfacing but is never as consequential as a missing DMARC policy, and a
// consumer needs to be able to tier them as a group rather than by name.
type AdjacentRecord struct {
	// Kind names the record: "mtasts", "tlsrpt", "bimi" or "caa".
	Kind string `json:"kind"`
	// Presence is whether it was found.
	Presence Presence `json:"presence"`
	// Detail is the salient parsed value where the record has one — the
	// MTA-STS enforcement mode, for instance. Empty where it has none.
	Detail string `json:"detail,omitempty"`
}

// Email is the structured email-authentication posture of a domain.
//
// Each check fills the part it gathered and leaves the rest nil, so a consumer
// merging results across checks can tell a control that was not published from
// one whose check did not run. Merging is the consumer's job because only it
// knows which checks it requested.
type Email struct {
	// Domain is the zone assessed.
	Domain string `json:"domain"`
	// SPF, DKIM and DMARC are the core authentication controls.
	SPF   *SPF   `json:"spf,omitempty"`
	DKIM  *DKIM  `json:"dkim,omitempty"`
	DMARC *DMARC `json:"dmarc,omitempty"`
	// Adjacent is the surrounding record this check gathered, if any.
	Adjacent *AdjacentRecord `json:"adjacent,omitempty"`
}
