package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/scanner"
)

// mtastsNoNetwork restricts the check to DNS, skipping the policy fetch.
var mtastsNoNetwork bool

// mtastsCmd represents the mtasts command
var mtastsCmd = &cobra.Command{
	Use:   "mtasts [domain]",
	Short: "Obtain the MTA-STS record and policy for a domain.",
	Long: `Lookup the _mta-sts TXT record for a domain to determine whether MTA-STS is
published. MTA-STS instructs sending mail servers to require TLS, preventing
downgrade and man-in-the-middle attacks on SMTP.

With --findings (or any structured output format) the policy file is also
retrieved from https://mta-sts.<domain>/.well-known/mta-sts.txt and assessed
against RFC 8461. This matters because the TXT record alone proves nothing: a
domain that advertises a policy it does not actually serve has the appearance
of protection without the substance, and senders have nothing to enforce.

Policy retrieval is the only part of this command that leaves DNS. Use
--no-network to restrict it to the TXT record alone.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Scoped to the invocation rather than package level, so the retained
		// policy cannot leak between runs.
		var mtastsPolicy analyse.MTASTSPolicy

		return runRecordCheck(context.Background(), args[0], recordCheck{
			name: "mtasts",
			retrieve: func(ctx context.Context, target string) ([]string, string, error) {
				return scanner.LookupMTASTSRecordsFrom(ctx, dnsClient, target)
			},
			analyse: func(ctx context.Context, o analyse.Origin, records []string) []finding.Finding {
				// A zero policy suppresses the rules that depend on the policy
				// file, rather than reporting them as failures.
				var policy analyse.MTASTSPolicy
				if len(records) > 0 && !mtastsNoNetwork {
					policy = scanner.FetchMTASTSPolicy(ctx, dnsClient, nil, o.Target)
				}
				// Retain the policy so it can be shown as evidence. Reporting a
				// verdict drawn from a document the operator cannot see would
				// make the result impossible to check.
				mtastsPolicy = policy

				var hosts []string
				if mx, err := scanner.LookupMX(ctx, dnsClient, o.Target); err == nil {
					hosts = mx
				}
				return analyse.MTASTS(o, records, policy, hosts)
			},
			render: func(records []string) {
				for _, r := range records {
					fmt.Println(strings.TrimSpace(r))
				}
			},
			evidence: func() []string {
				return policyLines(mtastsPolicy)
			},
		})
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	mtastsCmd.Flags().BoolVar(&mtastsNoNetwork, "no-network", false,
		"Restrict to DNS only, skipping retrieval of the MTA-STS policy file.")
	rootCmd.AddCommand(mtastsCmd)
}

// policyLines renders a fetched policy as individual records, so the retrieved
// evidence is readable rather than a whitespace-split blob. An unfetched policy
// yields nothing, which keeps --no-network runs honest about what was seen.
func policyLines(p analyse.MTASTSPolicy) []string {
	if !p.Fetched || p.Raw == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(p.Raw, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
