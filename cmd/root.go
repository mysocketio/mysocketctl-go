/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version             string
	date                string
	cfgFile             string
	email               string
	name                string
	socketType          string
	password            string
	port                int
	hostname            string
	sshkey              string
	protected           bool
	username            string
	socketID            string
	tunnelID            string
	identityFile        string
	cloudauth           bool
	cloudauth_addresses string
	cloudauth_domains   string
	createsshkey        bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "mysocketctl",
	Short:   "mysocket.io command line interface (CLI)",
	Version: version,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.SetVersionTemplate(fmt.Sprintf("mysocketctl:\nversion %s\ndate: %s\n", version, date))
}

func splitLongLines(b string, maxLength int) string {
	s := ""
	for {
		if len(b) > maxLength {
			s = s + b[0:maxLength] + "\n"
			b = b[maxLength:]
		} else {
			s = s + b
			break
		}
	}

	return s
}
