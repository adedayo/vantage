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
	"fmt"
	"os"
	"time"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	vantage "github.com/adedayo/vantage/pkg"
)

var (
	cfgFile string
	// resolvers holds the value of the --resolver flag.
	resolvers []string
	// queryTimeout holds the value of the --query-timeout flag.
	queryTimeout time.Duration
	// totalTimeout holds the value of the --timeout flag.
	totalTimeout time.Duration
	// queryRate holds the value of the --query-rate flag.
	queryRate int
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vantage",
	Short: "Audit the attack surface an organisation exposes.",
	// Long is assembled in Execute, because the banner carries the version and
	// that is only resolved at run time.
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.Version = versionString()
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	rootCmd.Long = banner() + `

vantage reports what an organisation exposes to someone looking at it, and
what that exposure would cost. It assesses mail authentication (SPF, DKIM,
DMARC), delegation and DNSSEC, certificate issuance policy, the hostnames
certificates have already published, subdomain takeover, and which providers
and jurisdictions the infrastructure actually resolves into.

Assessments are made from a vantage point, set with 'vantage audit --from'.
Only the external vantage — the public internet, with no privileged position
and no credentials — is implemented today.

Most evidence comes from DNS, which answers everybody. Certificate
Transparency logs and provider address ranges are also consulted, and the
egress each check makes is declared: see 'vantage audit --list-checks'.`

	if err := rootCmd.Execute(); err != nil {
		exit(err)
	}
}

func init() {
	cobra.OnInitialize(initConfig, initResolvers, initTimeouts)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.vantage.yaml)")
	rootCmd.PersistentFlags().StringSliceVar(&resolvers, "resolver", nil,
		"DNS resolver(s) to use, e.g. --resolver 1.1.1.1 --resolver 8.8.8.8:53. "+
			"Defaults to the platform's configured nameservers (resolv.conf on Linux/macOS, "+
			"the IP Helper API on Windows), falling back to public resolvers.")
	rootCmd.PersistentFlags().DurationVar(&queryTimeout, "query-timeout", vantage.DefaultQueryTimeout,
		"How long to wait for a single resolver before failing over to the next one. "+
			"Raise this on slow or lossy links.")
	rootCmd.PersistentFlags().DurationVar(&totalTimeout, "timeout", vantage.DefaultTotalTimeout,
		"Overall time budget for a lookup, across all resolvers.")
	rootCmd.PersistentFlags().IntVar(&queryRate, "query-rate", vantage.DefaultQueryRate,
		"Maximum DNS queries per second per resolver. Keeps concurrent audits from "+
			"tripping rate limiting, which would turn into spurious findings. 0 disables the limit.")

	registerOutputFlags(rootCmd)
}

// dnsClient is the resolver every command queries through. It is built once,
// from the flags and environment, before any command runs.
//
// The CLI is a single-assessment process, so one client is the whole of its
// configuration. The library keeps no equivalent: an embedding consumer builds
// its own client — or its own Resolver implementation — per assessment, which
// is what allows two runs under different scopes to coexist.
var dnsClient vantage.Resolver

// initResolvers builds the DNS client from the flags and environment.
//
// Precedence is flag, then environment, then platform discovery, then the
// well-known public resolvers — resolved once here rather than consulted on
// every query, so that what the audit was measured against cannot shift
// underneath a run in progress.
func initResolvers() {
	cfg := vantage.ConfigFromEnv()
	if len(resolvers) > 0 {
		cfg.Servers = resolvers
	}
	if rootCmd.PersistentFlags().Changed("query-timeout") {
		cfg.QueryTimeout = queryTimeout
	}
	if rootCmd.PersistentFlags().Changed("timeout") {
		cfg.TotalTimeout = totalTimeout
	}
	dnsClient = vantage.NewClient(cfg)
}

// initTimeouts applies the --query-rate flag. The timeout flags are folded
// into the client by initResolvers.
func initTimeouts() {
	if rootCmd.PersistentFlags().Changed("query-rate") {
		vantage.SetQueryRate(queryRate)
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".vantage" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".vantage")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
