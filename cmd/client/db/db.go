package db

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/mysocketio/mysocketctl-go/internal/client"
	"github.com/spf13/cobra"
)

var (
	hostname string
	port     int
)

func AddCommandsTo(client *cobra.Command) {
	addOneCommandTo(dbCmd, client)
	addOneCommandTo(mysqlCmd, client)
	addOneCommandTo(mycliCmd, client)
	addOneCommandTo(mysqlWorkbenchCmd, client)
	addOneCommandTo(dbeaverCmd, client)
}

func addOneCommandTo(cmdToAdd, cmdAddedTo *cobra.Command) {
	cmdToAdd.Flags().StringVarP(&hostname, "host", "", "", "Socket target host")
	cmdToAdd.Flags().IntVarP(&port, "port", "P", 0, "Socket port number")
	cmdAddedTo.AddCommand(cmdToAdd)
}

func dbNameFrom(args []string) string {
	var dbName string
	if len(args) > 0 {
		dbName = args[0]
	}
	return dbName
}

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Pick a socket host and connect to it as a database",
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			dbName string
			err    error
		)
		hostname, dbName, err = client.PickHostAndEnterDBName(hostname, dbNameFrom(args))
		if err != nil {
			return err
		}

		var dbClient string
		if err := survey.AskOne(&survey.Select{
			Message: "choose a client:",
			Options: []string{"mysql", "mysqlworkbench", "mycli", "dbeaver"},
		}, &dbClient); err != nil {
			return err
		}

		cmdToCall := "db:" + dbClient
		foundCmd, _, err := cmd.Parent().Find([]string{cmdToCall})
		if foundCmd.Use != cmdToCall || foundCmd.RunE == nil {
			return fmt.Errorf("couldn't find client subcommand %s", cmdToCall)
		}
		if len(args) == 0 && dbName != "" {
			args = append(args, dbName)
		}
		return foundCmd.RunE(foundCmd, args)
	},
}
