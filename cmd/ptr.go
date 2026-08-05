package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/adedayo/vantage/pkg/scanner"
)

// ptrCmd performs a reverse DNS (PTR) lookup.
var ptrCmd = &cobra.Command{
	Use:   "ptr [domain]",
	Short: "Perform a reverse PTR lookup for a domain's IP address.",
	Long: `Resolve the domain to its IP address and perform a reverse DNS (PTR) lookup.
PTR records are used to verify that an IP address maps back to the expected hostname,
which is a key indicator of legitimate mail server configuration and can flag
shadow infrastructure or unauthorised systems.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		ptr, err := scanner.ReverseLookupPTR(ctx, dnsClient, args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return err
		}
		fmt.Println(ptr)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(ptrCmd)
}
