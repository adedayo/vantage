package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/adedayo/vantage/pkg/scanner"
)

// dmarcReportCmd shows DMARC policy and aggregate/forensic report destinations.
var dmarcReportCmd = &cobra.Command{
	Use:   "dmarc-report [domain]",
	Short: "Show DMARC policy and reporting URIs (rua/ruf) for a domain.",
	Long: `Retrieve the full DMARC record for a domain and parse out the effective
policy (reject/quarantine/none) as well as the aggregate (rua) and forensic (ruf)
reporting URIs. Useful for verifying that DMARC reports are being collected and
that the policy is sufficiently strict to protect against spoofing.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		domain := args[0]

		policy, pErr := scanner.LookupDMARC(ctx, dnsClient, domain)
		rua, ruf, rErr := scanner.ParseDMARCReporting(ctx, dnsClient, domain)

		if pErr != nil && rErr != nil {
			fmt.Fprintln(os.Stderr, "no DMARC record found:", pErr)
			return pErr
		}

		if pErr == nil {
			fmt.Printf("Policy : %s\n", policy)
		}
		if rErr == nil {
			if len(rua) > 0 {
				fmt.Printf("RUA    : %s\n", strings.Join(rua, ", "))
			} else {
				fmt.Println("RUA    : (none)")
			}
			if len(ruf) > 0 {
				fmt.Printf("RUF    : %s\n", strings.Join(ruf, ", "))
			} else {
				fmt.Println("RUF    : (none)")
			}
		} else {
			fmt.Println("RUA    : (none)")
			fmt.Println("RUF    : (none)")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(dmarcReportCmd)
}
