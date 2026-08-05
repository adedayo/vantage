package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/scanner"
)

// caaCmd retrieves Certification Authority Authorization records.
var caaCmd = &cobra.Command{
	Use:   "caa [domain]",
	Short: "Retrieve CAA records for a domain.",
	Long: `Query DNS Certification Authority Authorization (CAA) records for a domain.
CAA records restrict which certificate authorities (CAs) are permitted to issue
TLS certificates for the domain, reducing the risk of mis-issuance.

The search climbs the domain tree as RFC 8659 requires, so a policy inherited
from a parent is found rather than reported as absent. With --findings (or any
structured output format) the policy is assessed rather than merely retrieved.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		// The climb result is captured here so that analysis can use the
		// source label and inheritance state without repeating the queries.
		var policy analyse.CAAPolicy

		return runRecordCheck(ctx, args[0], recordCheck{
			name: "caa",
			retrieve: func(ctx context.Context, target string) ([]string, string, error) {
				p, err := scanner.ClimbCAA(ctx, dnsClient, target)
				if err != nil {
					return nil, "", err
				}
				policy = p

				records := make([]string, 0, len(p.Records))
				for _, r := range p.Records {
					records = append(records, fmt.Sprintf("%d %s %q", r.Flags, r.Tag, r.Value))
				}
				return records, p.Source, nil
			},
			analyse: func(_ context.Context, o analyse.Origin, _ []string) []finding.Finding {
				return analyse.CAA(o, policy)
			},
			render: func(records []string) {
				for _, r := range records {
					fmt.Println(r)
				}
			},
		})
	},
}

func init() {
	rootCmd.AddCommand(caaCmd)
}
