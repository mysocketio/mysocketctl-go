package hosts

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/mysocketio/mysocketctl-go/internal/client"
	"github.com/spf13/cobra"
)

var (
	filteredTypes string
)

func AddCommandsTo(client *cobra.Command) {
	client.AddCommand(hostsCmd)
	hostsCmd.Flags().StringVarP(&filteredTypes, "types", "t", "prompt", "Filter by comma separated types, example: http,https,ssh,tls,database")
}

var hostsCmd = &cobra.Command{
	Use:     "hosts",
	Aliases: []string{"list", "ls"},
	Short:   "List client resources, socket names and their domains",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, err := client.ReadTokenOrAskToLogIn()
		if err != nil {
			return err
		}
		types, err := client.PickResourceTypes(filteredTypes)
		if err != nil {
			return err
		}
		resources, err := client.FetchResources(token, types...)
		if err != nil {
			return err
		}

		blue := color.New(color.FgBlue)

		tbl := table.NewWriter()
		tbl.AppendHeader(table.Row{"DNS Name", "Type", "Description"})
		for _, res := range resources.Resources {
			instruction := res.Instruction()
			if instruction != "" {
				instruction = "\n" + blue.Sprint(instruction)
			}
			tbl.AppendRow(table.Row{
				res.DomainsToString(),
				strings.ToUpper(res.SocketType),
				strings.Split(res.Description, ";")[0] + instruction,
			})
		}
		tbl.SetAutoIndex(true)
		tbl.Style().Options.SeparateRows = true

		fmt.Print(tbl.Render())
		return nil
	},
}
