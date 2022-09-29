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
	"strings"

	"github.com/jedib0t/go-pretty/table"
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/http"
	"github.com/mysocketio/mysocketctl-go/internal/ssh"
	"github.com/spf13/cobra"
)

// tunnelCmd represents the tunnel command
var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Manage your tunnels",
}

var tunnelListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List your tunnels",
	Run: func(cmd *cobra.Command, args []string) {
		if socketID == "" {
			log.Fatalf("error: --socket_id required")
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		tunnels := []models.Tunnel{}
		err = client.Request("GET", "socket/"+socketID+"/tunnel", &tunnels, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		ta := table.NewWriter()
		ta.AppendHeader(table.Row{"Socket ID", "Tunnel ID", "Tunnel Server", "Relay Port"})

		for _, t := range tunnels {
			ta.AppendRow(table.Row{socketID, t.TunnelID, t.TunnelServer, t.LocalPort})
		}

		ta.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", ta.Render())
	},
}

var tunnelDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a tunnel",
	Run: func(cmd *cobra.Command, args []string) {
		if socketID == "" {
			log.Fatalf("error: invalid socket_id")
		}
		if tunnelID == "" {
			log.Fatalf("error: invalid tunnel_id")
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		err = client.Request("DELETE", "socket/"+socketID+"/tunnel/"+tunnelID, nil, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		fmt.Println("Tunnel deleted")
	},
}

var tunnelCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a tunnel",
	Run: func(cmd *cobra.Command, args []string) {
		if socketID == "" {
			log.Fatalf("error: empty socket_id not allowed")
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		t := models.Tunnel{}
		err = client.Request("POST", "socket/"+socketID+"/tunnel", &t, models.Tunnel{})
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		ta := table.NewWriter()
		ta.AppendHeader(table.Row{"Socket ID", "Tunnel ID", "Tunnel Server", "Relay Port"})
		ta.AppendRow(table.Row{socketID, t.TunnelID, t.TunnelServer, t.LocalPort})

		ta.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", ta.Render())
	},
}

var tunnelConnectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect a tunnel",
	Run: func(cmd *cobra.Command, args []string) {
		if socketID == "" {
			log.Fatalf("error: invalid socket_id")
		}
		if tunnelID == "" {
			log.Fatalf("error: invalid tunnel_id")
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		socket := models.Socket{}
		err = client.Request("GET", "socket/"+socketID, &socket, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		if port < 1 {
			if socket.SocketType == "http" {
				if !httpserver {
					cmd.Help()
					log.Fatalf("error: port not specified")
				}
			} else if socket.SocketType == "ssh" {
				if !localssh {
					cmd.Help()
					log.Fatalf("error: port not specified")
				}
			} else {
				cmd.Help()
				log.Fatalf("error: port not specified")
			}
		}

		userID, _, err := http.GetUserID()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		userIDStr := *userID

		// Handle control + C
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		go func() {
			for {
				<-c
				log.Print("User disconnected...")
				os.Exit(0)
			}
		}()

		SetRlimit()

		if socketType != "http" && httpserver {
			httpserver = false
		}

		if socket.SocketType != "ssh" && localssh {
			localssh = false
		}

		org := models.Organization{}
		err = client.Request("GET", "organization", &org, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		err = ssh.SshConnect(userIDStr, socketID, tunnelID, port, hostname, identityFile, proxyHost, version, httpserver, localssh, org.Certificates["ssh_public_key"], "", httpserver_dir)
		if err != nil {
			fmt.Println(err)
		}
	},
}

func getTunnels(toComplete string) []string {
	var tunnelIDs []string

	if socketID == "" {
		return tunnelIDs
	}

	client, err := http.NewClient()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	tunnels := []models.Tunnel{}
	err = client.Request("GET", "socket/"+socketID+"/tunnel", &tunnels, nil)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error: %v", err))
	}

	for _, t := range tunnels {
		if strings.HasPrefix(t.TunnelID, toComplete) {
			tunnelIDs = append(tunnelIDs, t.TunnelID)
		}
	}

	return tunnelIDs
}

func init() {
	rootCmd.AddCommand(tunnelCmd)
	tunnelCmd.AddCommand(tunnelListCmd)
	tunnelCmd.AddCommand(tunnelCreateCmd)
	tunnelCmd.AddCommand(tunnelDeleteCmd)
	tunnelCmd.AddCommand(tunnelConnectCmd)

	tunnelDeleteCmd.Flags().StringVarP(&tunnelID, "tunnel_id", "t", "", "Tunnel ID")
	tunnelDeleteCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	tunnelDeleteCmd.MarkFlagRequired("tunnel_id")
	tunnelDeleteCmd.MarkFlagRequired("socket_id")
	tunnelDeleteCmd.RegisterFlagCompletionFunc("socket_id", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getSockets(toComplete), cobra.ShellCompDirectiveNoFileComp
	})
	tunnelDeleteCmd.RegisterFlagCompletionFunc("tunnel_id", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getTunnels(toComplete), cobra.ShellCompDirectiveNoFileComp
	})

	tunnelListCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	tunnelListCmd.MarkFlagRequired("socket_id")
	tunnelListCmd.RegisterFlagCompletionFunc("socket_id", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getSockets(toComplete), cobra.ShellCompDirectiveNoFileComp
	})

	tunnelCreateCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	tunnelCreateCmd.MarkFlagRequired("socket_id")
	tunnelCreateCmd.RegisterFlagCompletionFunc("socket_id", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getSockets(toComplete), cobra.ShellCompDirectiveNoFileComp
	})

	tunnelConnectCmd.Flags().StringVarP(&tunnelID, "tunnel_id", "t", "", "Tunnel ID")
	tunnelConnectCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	tunnelConnectCmd.Flags().StringVarP(&identityFile, "identity_file", "i", "", "Identity File")
	tunnelConnectCmd.Flags().IntVarP(&port, "port", "p", 0, "Port number")
	tunnelConnectCmd.Flags().StringVarP(&hostname, "host", "", "127.0.0.1", "Target host: Control where inbound traffic goes. Default localhost")
	tunnelConnectCmd.Flags().StringVarP(&proxyHost, "proxy", "", "", "Proxy host used for connection to mysocket.io")
	tunnelConnectCmd.Flags().BoolVarP(&localssh, "localssh", "", false, "Start a local SSH server to accept SSH sessions on this host")
	tunnelConnectCmd.Flags().BoolVarP(&localssh, "sshserver", "l", false, "Start a local SSH server to accept SSH sessions on this host")
	tunnelConnectCmd.MarkFlagRequired("tunnel_id")
	tunnelConnectCmd.MarkFlagRequired("socket_id")
	tunnelConnectCmd.Flags().MarkDeprecated("localssh", "use --sshserver instead")
	tunnelConnectCmd.Flags().BoolVarP(&httpserver, "httpserver", "", false, "Start a local http server to accept http connections on this host")
	tunnelConnectCmd.Flags().StringVarP(&httpserver_dir, "httpserver_dir", "", "", "Directory to serve http connections on this host")

	tunnelConnectCmd.RegisterFlagCompletionFunc("socket_id", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getSockets(toComplete), cobra.ShellCompDirectiveNoFileComp
	})
	tunnelConnectCmd.RegisterFlagCompletionFunc("tunnel_id", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getTunnels(toComplete), cobra.ShellCompDirectiveNoFileComp
	})
}
