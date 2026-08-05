package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/adedayo/vantage/pkg/scanner"
)

// tlsSSHCmd retrieves DANE TLSA records for SSH (_22._tcp).
var tlsSSHCmd = &cobra.Command{
	Use:   "ssh-dane [domain]",
	Short: "Retrieve DANE TLSA records for SSH service (_22._tcp).",
	Long: `Query TLSA records published under _22._tcp.<domain> to verify SSH host
key pinning via DANE (DNS-based Authentication of Named Entities). TLSA records
allow clients to authenticate the server's key material without relying on a
traditional PKI, reducing the risk of MITM attacks against SSH.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		result, err := scanner.LookupTLSASSH(ctx, dnsClient, args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return err
		}
		fmt.Println(result)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(tlsSSHCmd)
}
