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
	"io/ioutil"
	"log"
	"os"

	"github.com/jedib0t/go-pretty/table"
	"github.com/mysocketio/mysocketctl-go/internal/http"
	"github.com/spf13/cobra"
)

// accountCmd represents the account command
var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Create a new account or see account information.",
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new account",
	Run: func(cmd *cobra.Command, args []string) {
		if sshkey != "" {
			if _, err := os.Stat(sshkey); err == nil {
				dat, err := ioutil.ReadFile(sshkey)
				if err != nil {
					log.Fatalf("Unable to read the file %s, please check file permissions and try again (%v)", sshkey, err)
				}
				sshkey = string(dat)
			}
		}

		err := http.Register(name, email, password, sshkey)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		fmt.Println("Congratulation! your account has been created. Please check your email.")
		fmt.Println("Please complete the account registration by following the confirmation link in your email.")
		fmt.Println("After that login with login --email '<EMAIL>' --password '*****'")
	},
}

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show account information",
	Run: func(cmd *cobra.Command, args []string) {
		_, userID, err := http.GetUserID()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		account := http.Account{}
		err = client.Request("GET", "user/"+*userID, &account, nil)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		t := table.NewWriter()
		t.AppendRow(table.Row{"Name", account.Name})
		t.AppendRow(table.Row{"Email", account.Email})
		t.AppendRow(table.Row{"User ID", account.UserID})
		t.AppendRow(table.Row{"SSH Username", account.SshUsername})
		t.AppendRow(table.Row{"SSH Key", splitLongLines(account.SshKey, 80)})
		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())
	},
}

func init() {

	createCmd.Flags().StringVarP(&email, "email", "e", "", "your email address")
	createCmd.Flags().StringVarP(&name, "name", "n", "", "your name")
	createCmd.Flags().StringVarP(&password, "password", "p", "", "your pasword")
	createCmd.Flags().StringVarP(&sshkey, "sshkey", "s", "", "your public sshkey as a string or path, or use: --sshkey \"$(cat ~/.ssh/id_rsa.pub)\"")
	createCmd.MarkFlagRequired("email")
	createCmd.MarkFlagRequired("name")
	createCmd.MarkFlagRequired("password")
	createCmd.Flags().MarkHidden("sshkey")

	accountCmd.AddCommand(createCmd)
	accountCmd.AddCommand(showCmd)
	rootCmd.AddCommand(accountCmd)
}
