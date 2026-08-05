// Package audit assesses the attack surface a domain exposes, and is the
// entry point for embedding vantage in another tool.
//
// The contract is [Assessor], with two methods: [Assessor.Catalogue] reports
// what the library can assess, and [Assessor.Assess] does some of it. Build one
// with [NewAssessor] and drive it with a [Request].
//
//	assessor, err := audit.NewAssessor(resolver, audit.WithVersion("1.4.0"))
//	if err != nil {
//		return err
//	}
//	result, err := assessor.Assess(ctx, audit.Request{
//		Targets:   []string{"example.com"},
//		Selection: audit.Selection{Profile: audit.ProfileStandard},
//	})
//
// # Egress is injected, never ambient
//
// The resolver is a required argument rather than an option, and there is no
// package-level fallback. An assessor that invented its own egress would defeat
// any scope guard a caller wrapped around it, silently, at the moment it
// mattered most. The same applies to HTTP: pass [WithHTTPClient] to bound the
// checks that fetch a policy file or a page body. A caller enforcing scope must
// wrap both, since guarding DNS alone still discloses the target list to third
// parties through the HTTP path.
//
// Nothing configurable lives in package state. Two assessors, built under
// different authorisations, can run concurrently in one process without either
// observing the other's targets.
//
// # A nil error does not mean everything succeeded
//
// [Assessor.Assess] returns a non-nil error only when the run itself could not
// proceed. A check that fails is recorded against that check and the others
// continue, because one unreachable nameserver must not deny the caller the
// other twenty answers. Callers must therefore inspect Result.Checks and
// Result.Errors rather than treating a nil error as a clean bill of health.
//
// Each check settles on one of four states, and they are not reducible to a
// pass/fail pair:
//
//   - finding.StateOK — ran, the property was present
//   - finding.StateNotFound — ran, the property was definitively absent
//   - finding.StateNotChecked — did not run
//   - finding.StateCheckFailed — ran but could not reach a conclusion
//
// The distinction between not_found and check_failed is the one that matters:
// the first is a measurement, the second is the absence of one. A consumer that
// collapses them will report an unmeasured control as a passing control.
//
// # Building against declarations
//
// [Assessor.Catalogue] returns every check with the full catalogue of findings
// it can raise. A consumer mapping vantage's identifiers onto its own model
// should build that mapping against the catalogue and fail loudly on an unknown
// identifier, rather than hard-coding a list that drifts the moment a check is
// added upstream — at which point new findings arrive at run time with nowhere
// to go and are silently dropped.
//
// Capabilities.ThirdPartyEndpoints names every host the library may contact
// besides the targets themselves, so an operator can review egress before
// authorising a run. Obtaining the catalogue makes no network queries.
//
// # The registry is the single source of truth
//
// Registering a check is the only step needed to expose it to the profiles, to
// the CLI and to the capability manifest, so those surfaces cannot drift from
// what the tool actually does. The CLI is itself an [Assessor] consumer and
// prints what [Assessor.Catalogue] returns, which is what makes its
// --list-checks output evidence rather than documentation.
//
// See docs/embedding.md for a fuller guide.
package audit
