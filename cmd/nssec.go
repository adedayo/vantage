package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/adedayo/vantage/pkg/scanner"
)

// nssecCmd checks for NSEC/NSEC3 denial-of-existence records.
var nssecCmd = &cobra.Command{
	Use:   "nssec [domain]",
	Short: "Verify NSEC/NSEC3 denial-of-existence records for a domain.",
	Long: `Check whether a domain's DNS zone publishes NSEC or NSEC3 records as part
of DNSSEC. These records allow authenticated denial of existence of DNS names
and resource record sets, preventing zone enumeration with NSEC3 and enabling
DNSSEC chain-of-trust validation.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		found, err := scanner.VerifyNSSEC(ctx, dnsClient, args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return err
		}
		if found {
			fmt.Printf("NSEC/NSEC3: present for %s\n", args[0])
		} else {
			fmt.Printf("NSEC/NSEC3: not found for %s\n", args[0])
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(nssecCmd)
}
