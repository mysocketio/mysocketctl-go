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
	"log"
	"regexp"

	"os"

	"github.com/mysocketio/mysocketctl-go/internal/http"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to mysocket and get a token",
	Run: func(cmd *cobra.Command, args []string) {

		// Do version check
		latest_version, err := http.GetLatestVersion()
		if err != nil {
			log.Fatalf("error while checking for latest version: %v", err)
		}
		if latest_version != version {
			binary_path := os.Args[0]
			fmt.Printf("New version available. Please upgrade:\n%s version upgrade\n\n", binary_path)
		}
		// end version check

		// If email is not provided, then prompt for it
		if email == "" {
			fmt.Print("Email: ")
			fmt.Scanln(&email)
		}
		// Let's check if the email is a valid email address
		var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
		if len(email) < 3 && len(email) > 254 {
			log.Fatalf("error: invalid email address: %s", email)
		}
		if !emailRegex.MatchString(email) {
			log.Fatalf("error: invalid email address: %s", email)
		}

		// If password is not provided, then prompt for it.
		if password == "" {
			fmt.Print("Password: ")
			bytesPassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				fmt.Printf("Error getting password from prompt: %s \n", err)
				os.Exit(1)
			}
			password = string(bytesPassword)
			fmt.Print("\n")
		}
		err2 := http.Login(email, password)
		if err2 != nil {
			log.Fatalf("error: %v", err2)
		}

		fmt.Println("Login successful")
	},
}

func init() {
	loginCmd.Flags().StringVarP(&email, "email", "e", "", "Email address")
	loginCmd.Flags().StringVarP(&password, "password", "p", "", "Password")
	rootCmd.AddCommand(loginCmd)
}
