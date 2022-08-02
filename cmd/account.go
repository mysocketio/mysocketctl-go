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
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/http"
	"github.com/spf13/cobra"
)

// accountCmd represents the account command
var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Create a new account or see account information.",
}

var listOrgs = &cobra.Command{
	Use:   "list-orgs",
	Short: "List all organizations your user belongs to",
	Run: func(cmd *cobra.Command, args []string) {
		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		_, userID, err := http.GetUserID()
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		account := models.Account{}
		err = client.Request("GET", "user/"+*userID, &account, nil)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		orgs := []models.Organization{}
		err = client.Request("GET", "organizations/list", &orgs, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		t := table.NewWriter()
		t.AppendHeader(table.Row{"ID", "Name", "Current"})

		for _, s := range orgs {
			if s.ID == account.Organization.ID {
				t.AppendRow(table.Row{s.ID, s.Name, "Yes"})
			} else {
				t.AppendRow(table.Row{s.ID, s.Name, "No"})
			}

		}
		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())
	},
}

var switchOrg = &cobra.Command{
	Use:   "switch-org",
	Short: "Switch to a different organization",
	Run: func(cmd *cobra.Command, args []string) {

		form := models.SwitchOrgRequest{OrgName: orgName}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		val := &models.SwitchOrgResponse{}

		err = client.Request("POST", "users/organizations/switch", val, &form)

		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Switching to organization: %s\n", val.OrgName)
		f, err := os.Create(http.TokenFilePath())
		if err != nil {
			log.Fatal(err)
		}

		if err := os.Chmod(http.TokenFilePath(), 0600); err != nil {
			log.Fatal(err)
		}

		defer f.Close()
		_, err = f.WriteString(fmt.Sprintf("%s\n", val.Token))
		if err != nil {
			log.Fatal(err)
		}
	},
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

		account := models.Account{}
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

	switchOrg.Flags().StringVarP(&orgName, "org-name", "", "", "organization name")
	switchOrg.MarkFlagRequired("org-name")

	accountCmd.AddCommand(createCmd)
	accountCmd.AddCommand(showCmd)
	accountCmd.AddCommand(listOrgs)
	accountCmd.AddCommand(switchOrg)
	rootCmd.AddCommand(accountCmd)
}
