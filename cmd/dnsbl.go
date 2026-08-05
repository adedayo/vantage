package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/adedayo/vantage/pkg/scanner"
)

var dnsblBlocklist string

// dnsblCmd checks whether a domain's IP is listed in a DNS blocklist.
var dnsblCmd = &cobra.Command{
	Use:   "dnsbl [domain]",
	Short: "Check if a domain's IP is listed in a DNS blocklist (DNSBL).",
	Long: `Resolve the domain's IP address and query the specified DNS-based blocklist
(DNSBL) to determine whether the IP has been flagged for sending spam, malware,
or other malicious traffic. Useful for assessing the reputation of external-facing
hosts and identifying compromised or abused IP space.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		listed, err := scanner.CheckDNSBL(ctx, dnsClient, args[0], dnsblBlocklist)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return err
		}
		if listed {
			fmt.Printf("LISTED in %s: %s\n", dnsblBlocklist, args[0])
		} else {
			fmt.Printf("NOT LISTED in %s: %s\n", dnsblBlocklist, args[0])
		}
		return nil
	},
}

func init() {
	dnsblCmd.Flags().StringVarP(&dnsblBlocklist, "blocklist", "b", "zen.spamhaus.org",
		"DNSBL zone to query (default: zen.spamhaus.org)")
	rootCmd.AddCommand(dnsblCmd)
}
