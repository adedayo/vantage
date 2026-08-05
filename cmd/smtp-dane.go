package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/adedayo/vantage/pkg/scanner"
)

// smtpDaneCmd retrieves DANE TLSA records for SMTP (_25._tcp).
var smtpDaneCmd = &cobra.Command{
	Use:   "smtp-dane [domain]",
	Short: "Retrieve DANE TLSA records for the SMTP service (_25._tcp).",
	Long: `Query TLSA records published under _25._tcp.<domain> to verify that the mail
service pins its certificate via DANE, removing sole reliance on the public CA
hierarchy for SMTP transport security.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		result, err := scanner.LookupTLASSMTP(ctx, dnsClient, args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return err
		}
		fmt.Println(result)
		return nil
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.AddCommand(smtpDaneCmd)
}
