package cmd

import (
	"fmt"
	"log"

	"github.com/jedib0t/go-pretty/table"
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/http"
	"github.com/spf13/cobra"
)

var organizationCmd = &cobra.Command{
	Use:   "organization",
	Short: "organization related commands",
}

var organizationShowCmd = &cobra.Command{
	Use:   "show",
	Short: "show organization info",
	Run: func(cmd *cobra.Command, args []string) {

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		org := models.Organization{}
		err = client.Request("GET", "organization", &org, nil)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		t := table.NewWriter()
		t.AppendRow(table.Row{"Name", org.Name})
		t.AppendRow(table.Row{"ID", org.ID})
		t.AppendRow(table.Row{"Certificate Authority", org.Certificates["mtls_certificate"]})
		t.AppendRow(table.Row{"SSH Authority", org.Certificates["ssh_public_key"]})
		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())

	},
}

func init() {
	organizationCmd.AddCommand(organizationShowCmd)
	rootCmd.AddCommand(organizationCmd)
}
