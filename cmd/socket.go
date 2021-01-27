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
	"strconv"
	"strings"

	"github.com/mysocketio/mysocketctl-go/internal/http"
	"github.com/jedib0t/go-pretty/table"
	"github.com/spf13/cobra"
)

// socketCmd represents the socket command
var socketCmd = &cobra.Command{
	Use:   "socket",
	Short: "Manage your global sockets",
}

// socketsListCmd represents the socket ls command
var socketsListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List your sockets",
	Run: func(cmd *cobra.Command, args []string) {
		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		sockets := []http.Socket{}
		err = client.Request("GET", "connect", &sockets, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		var portsStr string

		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		t := table.NewWriter()
		t.AppendHeader(table.Row{"Socket ID", "DNS Name", "Port(s)", "Type", "Cloud Auth", "Name"})

		for _, s := range sockets {
			portsStr = ""
			for _, p := range s.SocketTcpPorts {
				i := strconv.Itoa(p)
				if portsStr == "" {
					portsStr = i
				} else {
					portsStr = portsStr + ", " + i
				}
			}

			t.AppendRow(table.Row{s.SocketID, s.Dnsname, portsStr, s.SocketType, s.CloudAuthEnabled, s.Name})
		}
		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())
	},
}

// socketCreateCmd represents the socket create command
var socketCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new socket",
	Run: func(cmd *cobra.Command, args []string) {
		if protected {
			if username == "" {
				log.Fatalf("error: --username required when using --protected")
			}
			if password == "" {
				log.Fatalf("error: --password required when using --protected")
			}
		}

		if name == "" {
			log.Fatalf("error: empty name not allowed")
		}

		var allowedEmailAddresses []string
		var allowedEmailDomains []string
		var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

		if cloudauth {
			for _, a := range strings.Split(cloudauth_addresses, ",") {
				email := strings.TrimSpace(a)
				if emailRegex.MatchString(email) {
					allowedEmailAddresses = append(allowedEmailAddresses, email)
				} else {
					log.Printf("Warning: ignoring invalid email %s", email)
				}
			}

			for _, d := range strings.Split(cloudauth_domains, ",") {
				domain := strings.TrimSpace(d)
				allowedEmailDomains = append(allowedEmailDomains, domain)
			}
		}

		socketType := strings.ToLower(socketType)
		if socketType != "http" && socketType != "https" && socketType != "tcp" && socketType != "tls" {
			log.Fatalf("error: --type should be either http, https, tcp or tls")
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		s := http.Socket{}
		newSocket := &http.Socket{
			Name:                  name,
			ProtectedSocket:       protected,
			SocketType:            socketType,
			ProtectedUsername:     username,
			ProtectedPassword:     password,
			CloudAuthEnabled:      cloudauth,
			AllowedEmailAddresses: allowedEmailAddresses,
			AllowedEmailDomains:   allowedEmailDomains,
		}
		err = client.Request("POST", "socket", &s, newSocket)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		t := table.NewWriter()
		t.AppendHeader(table.Row{"Socket ID", "DNS Name", "Port(s)", "Type", "Cloud Auth", "Name"})

		portsStr := ""
		for _, p := range s.SocketTcpPorts {
			i := strconv.Itoa(p)
			if portsStr == "" {
				portsStr = i
			} else {
				portsStr = portsStr + ", " + i
			}
		}

		t.AppendRow(table.Row{s.SocketID, s.Dnsname, portsStr, s.SocketType, s.CloudAuthEnabled, s.Name})
		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())

		if s.ProtectedSocket {
			tp := table.NewWriter()
			tp.AppendHeader(table.Row{"Username", "Password"})
			tp.AppendRow(table.Row{s.ProtectedUsername, s.ProtectedPassword})
			tp.SetStyle(table.StyleLight)
			fmt.Printf("\nProtected Socket:\n%s\n", tp.Render())
		}

		if s.CloudAuthEnabled {
			tc := table.NewWriter()
			tc.AppendHeader(table.Row{"Allowed email addresses", "Allowed email domains"})
			tc.AppendRow(table.Row{strings.Join(s.AllowedEmailAddresses, "\n"), strings.Join(s.AllowedEmailDomains, "\n")})
			tc.SetStyle(table.StyleLight)
			fmt.Printf("\nCloud Authentication, login details:\n%s\n", tc.Render())
		}
	},
}

// socketDeleteCmd represents the socket delete command
var socketDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a socket",
	Run: func(cmd *cobra.Command, args []string) {
		if socketID == "" {
			log.Fatalf("error: invalid socketid")
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		err = client.Request("DELETE", "socket/"+socketID, nil, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		fmt.Println("Socket deleted")
	},
}

func init() {
	rootCmd.AddCommand(socketCmd)
	socketCmd.AddCommand(socketsListCmd)
	socketCmd.AddCommand(socketCreateCmd)
	socketCmd.AddCommand(socketDeleteCmd)

	socketCreateCmd.Flags().StringVarP(&name, "name", "n", "", "Socket name")
	socketCreateCmd.Flags().BoolVarP(&protected, "protected", "p", false, "Protected, default no")
	socketCreateCmd.Flags().StringVarP(&username, "username", "u", "", "Username, required when protected set to true")
	socketCreateCmd.Flags().StringVarP(&password, "password", "", "", "Password, required when protected set to true")
	socketCreateCmd.Flags().BoolVarP(&cloudauth, "cloudauth", "c", false, "Enable oauth/oidc authentication")
	socketCreateCmd.Flags().StringVarP(&cloudauth_addresses, "allowed_email_addresses", "e", "", "Comma seperated list of allowed Email addresses when using cloudauth")
	socketCreateCmd.Flags().StringVarP(&cloudauth_domains, "allowed_email_domains", "d", "", "comma seperated list of allowed Email domain (i.e. 'example.com', when using cloudauth")
	socketCreateCmd.Flags().StringVarP(&socketType, "type", "t", "http", "Socket type, defaults to http")
	socketCreateCmd.MarkFlagRequired("name")

	socketDeleteCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	socketDeleteCmd.MarkFlagRequired("socket_id")
}
