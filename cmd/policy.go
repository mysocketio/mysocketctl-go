package cmd

import (
	"fmt"
	"log"
	"strings"

	"github.com/jedib0t/go-pretty/table"
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/http"
	"github.com/spf13/cobra"
)

// policyCmd represents the policy command
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage your global Policies",
}

// policysListCmd represents the policy ls command
var policysListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List your Policies",
	Run: func(cmd *cobra.Command, args []string) {
		client, err := http.NewClient()

		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		policiesPath := "policies"
		if perPage != 0 {
			policiesPath += fmt.Sprintf("?per_page=%d", perPage)
		}

		if page != 0 {
			if strings.Contains(policiesPath, "?") {
				policiesPath += fmt.Sprintf("&page=%d", page)
			} else {
				policiesPath += fmt.Sprintf("?page=%d", page)
			}
		}

		policys := []models.Policy{}
		err = client.Request("GET", "policies", &policys, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		t := table.NewWriter()
		t.AppendHeader(table.Row{"ID", "Name", "Description", "Socket IDs"})

		for _, s := range policys {
			var socketIDs string

			for _, p := range s.SocketIDs {
				if socketIDs == "" {
					socketIDs = socketIDs + ", " + p
				}

			}

			t.AppendRow(table.Row{s.ID, s.Name, s.Description, socketIDs})
		}
		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())
	},
}

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(policysListCmd)

	policysListCmd.Flags().Int64Var(&perPage, "per_page", 100, "The number of results to return per page.")
	policysListCmd.Flags().Int64Var(&page, "page", 0, "The page of results to return.")
}
