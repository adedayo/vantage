package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	vantage "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/audit"
	"github.com/adedayo/vantage/pkg/finding"
)

// recordCheck describes a single-record command in the terms the shared runner
// needs, so that every command gets consistent output, exit codes and error
// handling without repeating the plumbing.
type recordCheck struct {
	// name is the check identifier used in findings and posture output.
	name string
	// retrieve fetches the raw records for the target. It also reports the
	// resolver that answered, so that findings can be attributed to a source
	// and independently reproduced.
	retrieve func(ctx context.Context, target string) (records []string, source string, err error)
	// analyse turns retrieved records into findings. It may be nil for checks
	// whose rules are not yet implemented; the records are still reported.
	analyse func(ctx context.Context, o analyse.Origin, records []string) []finding.Finding
	// render writes the plain-text form of the records, preserving the
	// retrieval-only behaviour these commands have always had.
	render func(records []string)
	// evidence returns any additional material analyse gathered beyond the
	// DNS records, such as a fetched policy file. It is called after analyse
	// and its output is recorded alongside the records.
	//
	// Without this, a command could report a verdict drawn from a document the
	// operator never sees, leaving the finding impossible to verify.
	evidence func() []string
}

// runRecordCheck executes a single-record command.
//
// The behaviour deliberately splits three ways. In plain text without
// --findings it prints the record exactly as before. With --findings, or in any
// structured format, it emits the full envelope. This keeps the tool pleasant
// to use by hand while making it fully machine-consumable on request.
func runRecordCheck(ctx context.Context, target string, check recordCheck) error {
	structured := structuredOutput()
	if !structured && !showFindings {
		return runPlain(ctx, target, check)
	}

	result := newResult()
	result.AddTarget(target)

	records, source, err := check.retrieve(ctx, target)
	origin := analyse.Origin{Target: target, Source: source}
	switch {
	case err != nil && isNotFound(err):
		// Not found is a conclusion, not a failure. Recording it as a check
		// state rather than an error is what lets a consumer distinguish "this
		// control is absent" from "we could not tell".
		result.AddCheck(check.name, target, finding.StateNotFound)
		if check.analyse != nil {
			result.Add(check.analyse(ctx, origin, nil)...)
		}
	case err != nil:
		result.AddCheck(check.name, target, finding.StateCheckFailed)
		result.AddError(checkError(check.name, target, err))
	case len(records) == 0:
		result.AddCheck(check.name, target, finding.StateNotFound)
		if check.analyse != nil {
			result.Add(check.analyse(ctx, origin, nil)...)
		}
	default:
		// Analyse first, because it may retrieve further evidence — a policy
		// file, for instance — that belongs in the record list alongside the
		// DNS answers it was derived from.
		var findings []finding.Finding
		if check.analyse != nil {
			findings = check.analyse(ctx, origin, records)
		}
		if check.evidence != nil {
			records = append(records, check.evidence()...)
		}
		result.AddCheck(check.name, target, finding.StateOK, records...)
		result.Add(findings...)
	}

	return emit(result)
}

// runPlain preserves the original record-retrieval behaviour.
func runPlain(ctx context.Context, target string, check recordCheck) error {
	records, _, err := check.retrieve(ctx, target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return withExitCode(ExitError, err)
	}
	if len(records) == 0 {
		err := errors.New("error: not found")
		fmt.Fprintln(os.Stderr, err)
		return withExitCode(ExitError, err)
	}
	check.render(records)
	return nil
}

// isNotFound reports whether an error means the record is definitively absent,
// as opposed to the lookup having failed.
func isNotFound(err error) bool {
	return errors.Is(err, vantage.ErrNotFound) ||
		strings.Contains(err.Error(), "not found")
}

// checkError classifies a failure into a stable error code and a retry hint, so
// that automated consumers never have to interpret the message text.
//
// It delegates to the library rather than repeating the rules. The CLI's own
// copy classified by substring only, so a single-record command and an audit
// could label the same failure differently — an operator would then see one
// code interactively and another in the machine-readable output, with nothing
// to say which was right.
func checkError(check, target string, err error) finding.CheckError {
	return audit.ClassifyError(check, target, err)
}
