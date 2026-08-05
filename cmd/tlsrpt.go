package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/scanner"
)

// tlsrptCmd represents the tlsrpt command
var tlsrptCmd = &cobra.Command{
	Use:   "tlsrpt [domain]",
	Short: "Retrieve the SMTP TLS Reporting (TLS-RPT) record for a domain.",
	Long: `Query the _smtp._tls TXT record for a domain to determine where sending
servers should report failures to negotiate TLS with its mail exchangers.

Without TLS-RPT a downgrade attack, an expired certificate or a broken MTA-STS
policy produces no signal at all: mail simply travels in the clear, or stops,
and nobody is told. With --findings (or any structured output format) the record
is assessed against RFC 8460 rather than merely retrieved.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRecordCheck(context.Background(), args[0], recordCheck{
			name: "tlsrpt",
			retrieve: func(ctx context.Context, target string) ([]string, string, error) {
				return scanner.LookupTLSRPTRecordsFrom(ctx, dnsClient, target)
			},
			analyse: func(ctx context.Context, o analyse.Origin, records []string) []finding.Finding {
				return analyse.TLSRPT(o, records)
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
	rootCmd.AddCommand(tlsrptCmd)
}
