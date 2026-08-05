package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/adedayo/vantage/pkg/scanner"
)

// httpsDaneCmd represents the https-dane command
var httpsDaneCmd = &cobra.Command{
	Use:   "https-dane [domain]",
	Short: "Retrieve DANE TLSA records for the HTTPS service (_443._tcp).",
	Long: `Query TLSA records published under _443._tcp.<domain> to verify that the web
service pins its certificate via DANE, reducing exposure to CA mis-issuance and
rogue certificate authorities.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		result, err := scanner.LookupTLSAHTTPS(ctx, dnsClient, args[0])
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
	rootCmd.AddCommand(httpsDaneCmd)
}
