package db

import (
	"fmt"

	"github.com/mysocketio/mysocketctl-go/internal/client"
	"github.com/spf13/cobra"
)

var mycliCmd = &cobra.Command{
	Use:   "db:mycli",
	Short: "Connect to a database socket with mycli client",
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

		return client.ExecCommand("mycli", []string{
			"-h", hostname,
			"-P", fmt.Sprint(port),
			"--ssl-cert", crtPath,
			"--ssl-key", keyPath,
			dbName,
		}...)
	},
}
