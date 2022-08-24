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
	"strings"
	"syscall"
	"time"

	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/http"
	"github.com/mysocketio/mysocketctl-go/internal/ssh"
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

		if port == 0 {
			if socketType == "ssh" {
				if !localssh {
					cmd.Help()
					log.Fatalf("error: port not specified")
				}
			} else {
				cmd.Help()
				log.Fatalf("error: port not specified")
			}
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
			log.Fatalf("error: --type should be either http, https, tcp, database, ssh or tls")
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
				log.Fatalf("error: --upstream_type should be  mysql or postgres, defaults to mysql")
			}
		}

		connection := &models.Socket{
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

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		c := models.Socket{}
		err = client.WithVersion(version).Request("POST", "connect", &c, connection)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		fmt.Print(print_socket(c))

		userID, _, err2 := http.GetUserID()
		if err2 != nil {
			log.Fatalf("error: %v", err2)
		}

		userIDStr := *userID
		time.Sleep(1 * time.Second)
		ch := make(chan os.Signal)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-ch
			fmt.Println("cleaning up...")
			client, _ := http.NewClient()
			err = client.Request("DELETE", "socket/"+c.SocketID, nil, nil)
			if err != nil {
				log.Fatalf("error: %v", err)
			}
			os.Exit(0)
		}()

		SetRlimit()

		if socketType != "ssh" && localssh {
			localssh = false
		}

		org := models.Organization{}
		err = client.Request("GET", "organization", &org, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		ssh.SshConnect(userIDStr, c.SocketID, c.Tunnels[0].TunnelID, port, hostname, identityFile, proxyHost, version, localssh, org.Certificates["ssh_public_key"], "")
		if err != nil {
			fmt.Println(err)
		}

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
	connectCmd.Flags().StringVarP(&name, "description", "r", "", "Service description")
	connectCmd.Flags().BoolVarP(&protected, "protected", "", false, "Protected, default no")
	connectCmd.Flags().StringVarP(&username, "username", "u", "", "Username, required when protected set to true")
	connectCmd.Flags().StringVarP(&password, "password", "", "", "Password, required when protected set to true")
	connectCmd.Flags().StringVarP(&socketType, "type", "t", "http", "Socket type: http, https, ssh, tcp, tls, database")
	connectCmd.Flags().StringVarP(&identityFile, "identity_file", "i", "", "Identity File")
	connectCmd.Flags().StringVarP(&cloudauth_addresses, "allowed_email_addresses", "e", "", "Comma seperated list of allowed Email addresses when using cloudauth")
	connectCmd.Flags().StringVarP(&cloudauth_domains, "allowed_email_domains", "d", "", "comma seperated list of allowed Email domain (i.e. 'example.com', when using cloudauth")
	connectCmd.Flags().StringVarP(&upstream_username, "upstream_username", "j", "", "Upstream username used to connect to upstream database")
	connectCmd.Flags().StringVarP(&upstream_password, "upstream_password", "k", "", "Upstream password used to connect to upstream database")
	connectCmd.Flags().StringVarP(&upstream_http_hostname, "upstream_http_hostname", "", "", "Upstream http hostname")
	connectCmd.Flags().StringVarP(&upstream_type, "upstream_type", "", "", "Upstream type: Upstream type: http, https for http sockets or mysql, postgres for database sockets")
	connectCmd.Flags().StringVarP(&proxyHost, "proxy", "", "", "Proxy host used for connection to mysocket.io")
	connectCmd.Flags().BoolVarP(&localssh, "localssh", "l", false, "Start a local SSH server to accept SSH sessions on this host")
	connectCmd.MarkFlagRequired("name")

	rootCmd.AddCommand(connectCmd)
}
