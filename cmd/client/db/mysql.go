package db

import (
	"fmt"

	"github.com/mysocketio/mysocketctl-go/internal/client"
	"github.com/spf13/cobra"
)

var mysqlCmd = &cobra.Command{
	Use:   "db:mysql",
	Short: "Connect to a database socket with MySQL client",
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			dbName string
			err    error
		)
		hostname, dbName, err = client.PickHostAndEnterDBName(hostname, dbNameFrom(args))
		if err != nil {
			return err
		}

		_, _, crtPath, keyPath, port, err := client.GetOrgCert(hostname)
		if err != nil {
			return err
		}

		return client.ExecCommand("mysql", []string{
			"-h", hostname,
			"-P", fmt.Sprint(port),
			"--protocol", "TCP",
			"--ssl-cert", crtPath,
			"--ssl-key", keyPath,
			dbName,
		}...)
	},
}
