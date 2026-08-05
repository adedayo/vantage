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

// bimiCmd represents the bimi command
var bimiCmd = &cobra.Command{
	Use:   "bimi [domain]",
	Short: "Retrieve the Brand Indicators for Message Identification (BIMI) record.",
	Long: `Query the default._bimi TXT record for a domain, which tells mailbox providers
where to find the brand logo to display beside authenticated mail.

BIMI only takes effect when DMARC is enforcing, and most major providers also
require a Verified Mark Certificate. A record published without those
prerequisites is inert: it looks correct, costs money to obtain, and displays
nothing. With --findings (or any structured output format) those prerequisites
are checked rather than assumed.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRecordCheck(context.Background(), args[0], recordCheck{
			name: "bimi",
			retrieve: func(ctx context.Context, target string) ([]string, string, error) {
				return scanner.LookupBIMIRecordsFrom(ctx, dnsClient, target)
			},
			analyse: func(ctx context.Context, o analyse.Origin, records []string) []finding.Finding {
				return analyse.BIMI(o, records, dmarcEnforcing(ctx, o.Target))
			},
			render: func(records []string) {
				for _, r := range records {
					fmt.Println(r)
				}
			},
		})
	},
}

// dmarcEnforcing reports whether the domain publishes a quarantine or reject
// DMARC policy, which BIMI requires before any logo is displayed.
func dmarcEnforcing(ctx context.Context, domain string) bool {
	records, _, err := scanner.LookupDMARCRecordsFrom(ctx, dnsClient, domain)
	if err != nil {
		return false
	}
	for _, r := range records {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), "v=dmarc1") {
			continue
		}
		switch analyse.ParseDMARC(r).Policy {
		case "quarantine", "reject":
			return true
		}
	}
	return false
}

func init() {
	rootCmd.AddCommand(bimiCmd)
}
