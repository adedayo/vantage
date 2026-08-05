package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/scanner"
)

var dkimSelector string

// dkimCmd retrieves the DKIM public key record for a selector.
var dkimCmd = &cobra.Command{
	Use:   "dkim [domain]",
	Short: "Retrieve the DKIM public key record for a domain and selector.",
	Long: `Query the DKIM TXT record published at <selector>._domainkey.<domain>.
DKIM allows receiving mail servers to verify that a message was signed by the
sending domain and was not altered in transit.

With --findings (or any structured output format) the key is assessed against
RFC 6376 and RFC 8301 rather than merely retrieved: undersized RSA keys, revoked
selectors, test mode and malformed records are reported.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRecordCheck(context.Background(), args[0], recordCheck{
			name: "dkim",
			retrieve: func(ctx context.Context, target string) ([]string, string, error) {
				return scanner.LookupDKIMRecordsFrom(ctx, dnsClient, target, dkimSelector)
			},
			analyse: func(ctx context.Context, o analyse.Origin, records []string) []finding.Finding {
				keys := make([]analyse.DKIMKey, 0, len(records))
				for _, r := range records {
					keys = append(keys, analyse.ParseDKIM(dkimSelector, r))
				}
				// The selector was supplied by the caller, so an absence here
				// is an observation rather than a guess.
				return analyse.DKIM(o, keys, false)
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
	dkimCmd.Flags().StringVarP(&dkimSelector, "selector", "s", "default",
		"DKIM selector to query")
	rootCmd.AddCommand(dkimCmd)
}
