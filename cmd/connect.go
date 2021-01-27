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
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mysocketio/mysocketctl-go/internal/http"
	"github.com/mysocketio/mysocketctl-go/internal/ssh"
	"github.com/jedib0t/go-pretty/table"
	"github.com/spf13/cobra"
)

// connectCmd represents the connect command
var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Quickly connect, wrapper around sockets and tunnels",
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

		connection := &http.Socket{
			Name:                  name,
			ProtectedSocket:       protected,
			SocketType:            socketType,
			ProtectedUsername:     username,
			ProtectedPassword:     password,
			CloudAuthEnabled:      cloudauth,
			AllowedEmailAddresses: allowedEmailAddresses,
			AllowedEmailDomains:   allowedEmailDomains,
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		c := http.Socket{}
		err = client.Request("POST", "connect", &c, connection)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		t := table.NewWriter()
		t.AppendHeader(table.Row{"Socket ID", "DNS Name", "Port(s)", "Type", "Cloud Auth", "Name"})

		portsStr := ""
		for _, p := range c.SocketTcpPorts {
			i := strconv.Itoa(p)
			if portsStr == "" {
				portsStr = i
			} else {
				portsStr = portsStr + ", " + i
			}
		}

		t.AppendRow(table.Row{c.SocketID, c.Dnsname, portsStr, c.SocketType, c.CloudAuthEnabled, c.Name})
		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())

		if c.ProtectedSocket {
			tp := table.NewWriter()
			tp.AppendHeader(table.Row{"Username", "Password"})
			tp.AppendRow(table.Row{c.ProtectedUsername, c.ProtectedPassword})
			tp.SetStyle(table.StyleLight)
			fmt.Printf("\nProtected Socket:\n%s\n", tp.Render())
		}

		if c.CloudAuthEnabled {
			tc := table.NewWriter()
			tc.AppendHeader(table.Row{"Allowed email addresses", "Allowed email domains"})
			tc.AppendRow(table.Row{strings.Join(c.AllowedEmailAddresses, "\n"), strings.Join(c.AllowedEmailDomains, "\n")})
			tc.SetStyle(table.StyleLight)
			fmt.Printf("\nCloud Authentication, login details:\n%s\n", tc.Render())
		}

		userID, _, err2 := http.GetUserID()
		if err2 != nil {
			log.Fatalf("error: %v", err2)
		}

		userIDStr := *userID
		time.Sleep(2 * time.Second)
		ch := make(chan os.Signal)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-ch
			fmt.Println("cleaning up...")
			client, err := http.NewClient()
			err = client.Request("DELETE", "socket/"+c.SocketID, nil, nil)
			if err != nil {
				log.Fatalf("error: %v", err)
			}
			os.Exit(0)
		}()

		SetRlimit()
		ssh.SshConnect(userIDStr, c.SocketID, c.Tunnels[0].TunnelID, port, hostname, identityFile)
		fmt.Println("cleaning up...")
		client, err = http.NewClient()

		err = client.Request("DELETE", "socket/"+c.SocketID, nil, nil)
		if err != nil {
			log.Fatalf("error: %v", err)
		}
	},
}

func init() {
	connectCmd.Flags().IntVarP(&port, "port", "p", 0, "Port")
	connectCmd.Flags().StringVarP(&hostname, "host", "", "127.0.0.1", "Target host: Control where inbound traffic goes. Default localhost")
	connectCmd.Flags().StringVarP(&name, "name", "n", "", "Service name")
	connectCmd.Flags().BoolVarP(&protected, "protected", "", false, "Protected, default no")
	connectCmd.Flags().StringVarP(&username, "username", "u", "", "Username, required when protected set to true")
	connectCmd.Flags().StringVarP(&password, "password", "", "", "Password, required when protected set to true")
	connectCmd.Flags().StringVarP(&socketType, "type", "t", "http", "Socket type: http, https, tcp, tls")
	connectCmd.Flags().StringVarP(&identityFile, "identity_file", "i", "", "Identity File")
	connectCmd.Flags().BoolVarP(&cloudauth, "cloudauth", "c", false, "Enable oauth/oidc authentication")
	connectCmd.Flags().StringVarP(&cloudauth_addresses, "allowed_email_addresses", "e", "", "Comma seperated list of allowed Email addresses when using cloudauth")
	connectCmd.Flags().StringVarP(&cloudauth_domains, "allowed_email_domains", "d", "", "comma seperated list of allowed Email domain (i.e. 'example.com', when using cloudauth")
	connectCmd.MarkFlagRequired("port")
	connectCmd.MarkFlagRequired("name")

	rootCmd.AddCommand(connectCmd)
}
