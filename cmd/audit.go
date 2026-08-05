package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/adedayo/vantage/pkg/audit"
)

var (
	auditProfile          string
	auditVantage          string
	auditChecks           []string
	auditSkipChecks       []string
	auditDomainsFile      string
	auditStdin            bool
	auditConcurrency      int
	auditCheckConcurrency int
	auditMaxTargets       int
	auditNoNetwork        bool
	auditProgress         bool
	auditListChecks       bool
	auditHosts            []string
	auditHostsFile        string

	auditEnumerate           bool
	auditExpectJurisdictions []string
)

var auditCmd = &cobra.Command{
	Use:   "audit [domain...]",
	Short: "Assess the attack surface of one or more domains.",
	Long: `Run every applicable check against one or more domains and report a single
consolidated result.

This is the primary entry point: rather than invoking each check separately and
correlating the output by hand, audit fans out concurrently, shares DNS answers
between checks, and reports prioritised findings with the evidence behind them.

Targets may be given as arguments, in a file with --domains-file, or on standard
input with --stdin.

  vantage audit example.com
  vantage audit example.com acme.co.uk --profile email
  vantage audit --domains-file portfolio.txt -o ndjson --fail-on high

Only passive DNS queries are made. You are responsible for having authority to
assess the domains you target.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		assessor, err := newAssessor()
		if err != nil {
			return err
		}

		if auditListChecks {
			return listChecks(cmd.Context(), assessor)
		}

		profile, err := audit.ParseProfile(auditProfile)
		if err != nil {
			return withExitCode(ExitUsage, err)
		}

		if _, err := audit.ParseVantage(auditVantage); err != nil {
			return withExitCode(ExitUsage, err)
		}

		selection := audit.Selection{
			Profile:   profile,
			Only:      auditChecks,
			Skip:      auditSkipChecks,
			NoNetwork: auditNoNetwork,
		}
		// Resolved here as well as inside Assess so that a bad selection fails
		// with exit code 2 before any target is read, rather than as a generic
		// runtime error after the operator has waited.
		checks, err := selection.Resolve()
		if err != nil {
			return withExitCode(ExitUsage, err)
		}
		if len(checks) == 0 {
			return withExitCode(ExitUsage,
				fmt.Errorf("error: no checks selected; see 'vantage audit --list-checks'"))
		}

		targets, err := collectTargets(args)
		if err != nil {
			return err
		}

		hosts, err := collectHosts()
		if err != nil {
			return err
		}

		req := audit.Request{
			Targets:             targets,
			Selection:           selection,
			Hosts:               hosts,
			Enumerate:           auditEnumerate,
			ExpectJurisdictions: auditExpectJurisdictions,
			Concurrency:         auditConcurrency,
			CheckConcurrency:    auditCheckConcurrency,
		}
		// Progress goes to stderr so that redirecting stdout still yields a
		// clean document, and is suppressed for structured output and when
		// stdout is not a terminal.
		if showProgress(len(targets)) {
			req.Observer = progressWriter(os.Stderr, len(targets))
		}

		result, err := assessor.Assess(cmd.Context(), req)
		if err != nil {
			return withExitCode(ExitError, err)
		}
		return emit(result)
	},
}

// newAssessor builds the library entry point from the process's configuration.
//
// The CLI goes through the same embedding contract as any other consumer. That
// is the point of doing it: an interface with one implementation and one caller
// is a guess about what embedders need, and the shape of Request and
// Capabilities is only trustworthy once something else has had to live with it.
// Where the CLI needs a private hook, the interface is wrong.
func newAssessor() (audit.Assessor, error) {
	v, _, _ := buildInfo()
	a, err := audit.NewAssessor(dnsClient, audit.WithVersion(v))
	if err != nil {
		// A missing resolver is a configuration fault, not a target failure.
		return nil, withExitCode(ExitError, err)
	}
	return a, nil
}

// collectHosts gathers the hostnames to assess for subdomain takeover.
//
// Nothing is inferred: only names the operator supplied are examined. Guessing
// subdomains would be enumeration by brute force, which spec 012 forbids, and
// would report on hosts the domain never published.
func collectHosts() ([]string, error) {
	hosts := append([]string{}, auditHosts...)
	if auditHostsFile != "" {
		fromFile, err := readTargets(auditHostsFile)
		if err != nil {
			return nil, withExitCode(ExitUsage, err)
		}
		hosts = append(hosts, fromFile...)
	}
	return hosts, nil
}

// collectTargets gathers targets from arguments, a file and standard input,
// applying the safety cap.
func collectTargets(args []string) ([]string, error) {
	targets := append([]string{}, args...)

	if auditDomainsFile != "" {
		fromFile, err := readTargets(auditDomainsFile)
		if err != nil {
			return nil, withExitCode(ExitUsage, err)
		}
		targets = append(targets, fromFile...)
	}

	if auditStdin {
		fromStdin, err := readTargetLines(bufio.NewScanner(os.Stdin))
		if err != nil {
			return nil, withExitCode(ExitError, err)
		}
		targets = append(targets, fromStdin...)
	}

	if len(targets) == 0 {
		return nil, withExitCode(ExitUsage, fmt.Errorf(
			"error: no domains supplied; pass them as arguments, with --domains-file, or with --stdin"))
	}

	// The cap is a safety valve rather than a limitation: it stops a mistaken
	// input file, or an automated caller with a bad plan, from turning into a
	// very large volume of queries against third-party infrastructure.
	if auditMaxTargets > 0 && len(targets) > auditMaxTargets {
		return nil, withExitCode(ExitUsage, fmt.Errorf(
			"error: %d targets exceeds the --max-targets limit of %d",
			len(targets), auditMaxTargets))
	}
	return targets, nil
}

func readTargets(path string) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // the path is supplied by the operator
	if err != nil {
		return nil, fmt.Errorf("error: cannot read domains file: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only file

	return readTargetLines(bufio.NewScanner(f))
}

// readTargetLines reads one target per line, ignoring blanks and # comments.
func readTargetLines(scanner *bufio.Scanner) ([]string, error) {
	var targets []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Tolerate trailing comments and inline whitespace.
		if idx := strings.IndexAny(line, " \t#"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error: reading targets: %w", err)
	}
	return targets, nil
}

// showProgress reports whether to draw a progress indicator.
//
// A single target now qualifies. It did not when progress was reported only on
// target completion, because the single event arrived as the run ended; with
// per-check reporting there is something to show throughout, and a lone
// domain assessed with the deep profile is exactly when a user most wants to
// see that the tool is still working.
func showProgress(targets int) bool {
	if !auditProgress || quiet || structuredOutput() {
		return false
	}
	return targets > 0 && isTerminal(os.Stderr)
}

// progressWriter renders progress events as a single rewritten line on w.
//
// Only completion events are drawn. Reporting a check as it starts would make
// the line flicker between checks that finish instantly, and would overstate
// advancement: a check that has started has assessed nothing yet.
func progressWriter(w io.Writer, totalTargets int) func(audit.Progress) {
	var mu sync.Mutex
	return func(p audit.Progress) {
		if p.Phase == audit.PhaseTargetStarted {
			return
		}
		mu.Lock()
		defer mu.Unlock()

		if totalTargets == 1 {
			fmt.Fprintf(w, "\r  %s: %d/%d checks%s",
				p.Target, p.ChecksDone, p.ChecksTotal, strings.Repeat(" ", 12))
		} else {
			fmt.Fprintf(w, "\r  assessed %d/%d (%s)%s",
				p.TargetsDone, p.TargetsTotal, p.Target, strings.Repeat(" ", 12))
		}
		if p.Phase == audit.PhaseTargetCompleted && p.TargetsDone == p.TargetsTotal {
			fmt.Fprintln(w)
		}
	}
}

// listChecks prints the registered checks and what they cost.
//
// It reads the assessor's catalogue rather than the package registry, so that
// what the CLI advertises is exactly what an embedding consumer would be told.
// If those two could differ, --list-checks would be documentation rather than
// evidence.
//
// The blast radius shown is generated from each check's declared egress
// profile, not maintained alongside it, so it cannot describe a check as
// touching less than it does.
func listChecks(ctx context.Context, assessor audit.Assessor) error {
	caps, err := assessor.Catalogue(ctx)
	if err != nil {
		return withExitCode(ExitError, err)
	}

	fmt.Printf("%-10s %-9s %-46s %s\n", "CHECK", "QUERIES", "EGRESS", "SUMMARY")
	for _, c := range caps.Checks {
		fmt.Printf("%-10s %-9d %-46s %s\n",
			c.Name, c.TypicalQueries, c.Egress.Describe(), c.Summary)
	}

	if len(caps.ThirdPartyEndpoints) > 0 {
		fmt.Printf("\nTHIRD-PARTY ENDPOINTS\n%s\n",
			strings.Join(caps.ThirdPartyEndpoints, ", "))
	}

	fmt.Printf("\n%-10s %s\n", "PROFILE", "CONTENTS")
	for _, p := range caps.Profiles {
		fmt.Printf("%-10s %s\n", p.Name, p.Summary)
	}
	return nil
}

func init() {
	f := auditCmd.Flags()
	f.StringVar(&auditProfile, "profile", string(audit.ProfileStandard),
		fmt.Sprintf("Breadth of assessment: %s.", strings.Join(audit.Profiles(), ", ")))
	f.StringVar(&auditVantage, "from", string(audit.DefaultVantage),
		fmt.Sprintf("Vantage point to assess from: %s.", strings.Join(audit.Vantages(), ", ")))
	f.StringSliceVar(&auditChecks, "checks", nil,
		"Run only these checks, overriding the profile.")
	f.StringSliceVar(&auditSkipChecks, "skip-checks", nil,
		"Skip these checks. Applied after --checks.")
	f.StringVar(&auditDomainsFile, "domains-file", "",
		"Read targets from a file, one per line. Blank lines and # comments are ignored.")
	f.BoolVar(&auditStdin, "stdin", false, "Read targets from standard input.")
	f.IntVar(&auditConcurrency, "concurrency", audit.DefaultConcurrency,
		"How many domains to assess in parallel.")
	f.IntVar(&auditCheckConcurrency, "check-concurrency", audit.DefaultCheckConcurrency,
		"How many checks to run in parallel per domain.")
	f.IntVar(&auditMaxTargets, "max-targets", 0,
		"Refuse to run if more than this many targets are supplied. 0 means no limit.")
	f.BoolVar(&auditNoNetwork, "no-network", false,
		"Restrict to DNS only, excluding checks that need other egress.")
	f.BoolVar(&auditProgress, "progress", true,
		"Show progress on stderr when assessing several domains interactively.")
	f.BoolVar(&auditListChecks, "list-checks", false,
		"List the available checks and profiles, then exit.")
	f.StringSliceVar(&auditHosts, "hosts", nil,
		"Additional hostnames to assess for subdomain takeover, e.g. www.example.com.")
	f.StringVar(&auditHostsFile, "hosts-file", "",
		"Read hostnames to assess for subdomain takeover from a file, one per line.")
	f.BoolVar(&auditEnumerate, "enumerate", false,
		"Discover additional hostnames from Certificate Transparency logs and assess them too. "+
			"This queries a third-party log service.")
	f.StringSliceVar(&auditExpectJurisdictions, "expect-jurisdiction", nil,
		"ISO 3166-1 alpha-2 country codes infrastructure is expected to be hosted in, e.g. GB,IE. "+
			"Without this, the jurisdiction rule is not evaluated.")

	rootCmd.AddCommand(auditCmd)
}
