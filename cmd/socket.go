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
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/jedib0t/go-pretty/table"
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/http"
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

		sockets := []models.Socket{}
		err = client.Request("GET", "connect", &sockets, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		var portsStr string

		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		t := table.NewWriter()
		t.AppendHeader(table.Row{"Socket ID", "DNS Name", "Port(s)", "Type", "Cloud Auth", "Description"})

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

			t.AppendRow(table.Row{s.SocketID, s.Dnsname, portsStr, s.SocketType, s.Description})
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

		for _, a := range strings.Split(cloudauth_addresses, ",") {
			email := strings.TrimSpace(a)
			if emailRegex.MatchString(email) {
				allowedEmailAddresses = append(allowedEmailAddresses, email)
			} else {
				if email != "" {
					log.Printf("Warning: ignoring invalid email %s", email)
				}
			}
		}

		for _, d := range strings.Split(cloudauth_domains, ",") {
			domain := strings.TrimSpace(d)
			if domain != "" {
				allowedEmailDomains = append(allowedEmailDomains, domain)
			}
		}
		if len(allowedEmailDomains) == 0 && len(allowedEmailAddresses) == 0 {
			log.Println("No Email or Email Domains were provided.")
			log.Println("No-one will have access.")
			os.Exit(1)
		}

		socketType := strings.ToLower(socketType)
		if socketType != "http" && socketType != "https" && socketType != "tcp" && socketType != "tls" && socketType != "ssh" && socketType != "database" {
			log.Fatalf("error: --type should be either http, https, ssh, database, tcp or tls")
		}

		if socketType == "database" {
			if upstream_username == "" {
				log.Fatalln("Upstream Username required for database sockets")
			}
			if upstream_password == "" {
				log.Fatalln("Upstream Password required for database sockets")
			}
		}

		upstreamType := strings.ToLower(upstream_type)
		if socketType == "http" || socketType == "https" {
			if upstreamType != "http" && upstreamType != "https" && upstreamType != "" {
				log.Fatalf("error: --upstream_type should be either http, https")
			}
		}

		if socketType == "database" {
			if upstreamType != "mysql" && upstreamType != "postgres" && upstreamType != "" {
				log.Fatalf("error: --upstream_type should be mysql or postgres, defaults to mysql")
			}
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		s := models.Socket{}
		newSocket := &models.Socket{
			Name:                  name,
			Description:           description,
			ProtectedSocket:       protected,
			SocketType:            socketType,
			ProtectedUsername:     username,
			ProtectedPassword:     password,
			AllowedEmailAddresses: allowedEmailAddresses,
			AllowedEmailDomains:   allowedEmailDomains,
			UpstreamUsername:      upstream_username,
			UpstreamPassword:      upstream_password,
			UpstreamHttpHostname:  upstream_http_hostname,
			UpstreamType:          upstreamType,
		}
		err = client.WithVersion(version).Request("POST", "socket", &s, newSocket)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}
		fmt.Print(print_socket(s))
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

// socketShowCmd represents the socket delete command
var socketShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show socket details",
	Run: func(cmd *cobra.Command, args []string) {
		if socketID == "" {
			log.Fatalf("error: invalid socketid")
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		socket := models.Socket{}
		err = client.Request("GET", "socket/"+socketID, &socket, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}
		fmt.Print(print_socket(socket))
	},
}

func getSockets(toComplete string) []string {
	var socketIDs []string

	client, err := http.NewClient()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	sockets := []models.Socket{}
	err = client.Request("GET", "socket", &sockets, nil)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error: %v", err))
	}

	for _, s := range sockets {
		if strings.HasPrefix(s.SocketID, toComplete) {
			socketIDs = append(socketIDs, s.SocketID)
		}
	}

	return socketIDs
}

func init() {
	rootCmd.AddCommand(socketCmd)
	socketCmd.AddCommand(socketsListCmd)
	socketCmd.AddCommand(socketCreateCmd)
	socketCmd.AddCommand(socketDeleteCmd)
	socketCmd.AddCommand(socketShowCmd)

	socketCreateCmd.Flags().StringVarP(&name, "name", "n", "", "Socket name")
	socketCreateCmd.Flags().StringVarP(&description, "description", "r", "", "Socket description")
	socketCreateCmd.Flags().BoolVarP(&protected, "protected", "p", false, "Protected, default no")
	socketCreateCmd.Flags().StringVarP(&username, "username", "u", "", "Username, required when protected set to true")
	socketCreateCmd.Flags().StringVarP(&password, "password", "", "", "Password, required when protected set to true")
	socketCreateCmd.Flags().StringVarP(&cloudauth_addresses, "allowed_email_addresses", "e", "", "Comma seperated list of allowed Email addresses when using cloudauth")
	socketCreateCmd.Flags().StringVarP(&cloudauth_domains, "allowed_email_domains", "d", "", "comma seperated list of allowed Email domain (i.e. 'example.com', when using cloudauth")
	socketCreateCmd.Flags().StringVarP(&upstream_username, "upstream_username", "j", "", "Upstream username used to connect to upstream database")
	socketCreateCmd.Flags().StringVarP(&upstream_password, "upstream_password", "k", "", "Upstream password used to connect to upstream database")
	socketCreateCmd.Flags().StringVarP(&upstream_http_hostname, "upstream_http_hostname", "", "", "Upstream http hostname")
	socketCreateCmd.Flags().StringVarP(&upstream_type, "upstream_type", "", "", "Upstream type: http, https for http sockets or mysql, postgres for database sockets")
	socketCreateCmd.Flags().StringVarP(&socketType, "type", "t", "http", "Socket type: http, https, ssh, tcp, tls, database")
	socketCreateCmd.MarkFlagRequired("name")

	socketDeleteCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	socketDeleteCmd.MarkFlagRequired("socket_id")
	socketDeleteCmd.RegisterFlagCompletionFunc("socket_id", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getSockets(toComplete), cobra.ShellCompDirectiveNoFileComp
	})

	socketShowCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	socketShowCmd.MarkFlagRequired("socket_id")
	socketShowCmd.RegisterFlagCompletionFunc("socket_id", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getSockets(toComplete), cobra.ShellCompDirectiveNoFileComp
	})

}
