/*
Copyright © 2021 Adedayo Adetoye (aka Dayo)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

 3. Neither the name of the copyright holder nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/adedayo/vantage/pkg/analyse"
	"github.com/adedayo/vantage/pkg/finding"
	"github.com/adedayo/vantage/pkg/scanner"
)

// spfCmd represents the spf command
var spfCmd = &cobra.Command{
	Use:   "spf [domain]",
	Short: "Retrieve the Sender Policy Framework (SPF) record for a domain.",
	Long: `Query the SPF TXT record for a domain to determine which mail servers
are permitted to send email on its behalf. Useful for detecting mail spoofing risk.

With --findings (or any structured output format) the record is assessed against
RFC 7208 rather than merely retrieved: permissive terminal mechanisms, duplicate
records, deprecated mechanisms and overly broad address ranges are reported.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRecordCheck(context.Background(), args[0], recordCheck{
			name: "spf",
			retrieve: func(ctx context.Context, target string) ([]string, string, error) {
				return scanner.LookupSPFRecordsFrom(ctx, dnsClient, target)
			},
			analyse: func(ctx context.Context, o analyse.Origin, records []string) []finding.Finding {
				return analyse.SPFRecursive(ctx, o, scanner.SPFResolver{},
					records, scanner.SendsMail(ctx, dnsClient, o.Target))
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
	rootCmd.AddCommand(spfCmd)
}
