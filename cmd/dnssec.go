package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	vantage "github.com/adedayo/vantage/pkg"
	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/scanner"
)

// dnssecCmd assesses a domain's DNSSEC deployment.
var dnssecCmd = &cobra.Command{
	Use:   "dnssec [domain]",
	Short: "Assess a domain's DNSSEC chain of trust.",
	Long: `Assess DNSSEC for a domain: the keys it publishes, whether the parent zone
delegates trust to them with a DS record, the signing algorithms and key sizes
in use, how soon its signatures expire, and which form of authenticated denial
of existence it serves.

The distinction that matters is between a zone that is signed and a zone that
validates. DNSKEY records alone prove only that signing is switched on; without
a matching DS record at the parent no resolver on the internet ever uses those
signatures. The report also states whether the answering resolver set the AD
bit, which separates "this zone is signed" from "my resolver validates it".

With --findings (or any structured output format) the deployment is assessed
rather than merely reported.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		// The retrieved zone is captured so that analysis reasons about exactly
		// the evidence that was printed, without repeating the queries.
		var zone analyse.DNSSECZone

		return runRecordCheck(ctx, args[0], recordCheck{
			name: "dnssec",
			retrieve: func(ctx context.Context, target string) ([]string, string, error) {
				z, err := scanner.FetchDNSSECZone(ctx, dnsClient, target)
				if err != nil {
					return nil, "", err
				}
				zone = z
				if !z.Signed() {
					// Wrapping ErrNotFound keeps the shared runner's
					// absent-record handling, while saying plainly what is
					// absent: a bare "not found" leaves the reader guessing
					// whether the check failed or the zone is unsigned.
					return nil, z.Source, fmt.Errorf(
						"error: DNSSEC is not enabled for %s: %w", target, vantage.ErrNotFound)
				}
				return analyse.DNSSECRecords(z), z.Source, nil
			},
			analyse: func(_ context.Context, o analyse.Origin, _ []string) []finding.Finding {
				return analyse.DNSSEC(o, zone)
			},
			render: func(records []string) {
				for _, r := range records {
					fmt.Println(r)
				}
			},
		})
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.AddCommand(dnssecCmd)
}
