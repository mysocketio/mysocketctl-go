package db

import (
	"fmt"

	"github.com/mysocketio/mysocketctl-go/client/preference"
	"github.com/mysocketio/mysocketctl-go/internal/client"
	"github.com/mysocketio/mysocketctl-go/internal/enum"
	"github.com/spf13/cobra"
)

var mycliCmd = &cobra.Command{
	Use:   "db:mycli",
	Short: "Connect to a database socket with mycli client",
	RunE: func(cmd *cobra.Command, args []string) error {
		pickedHost, err := client.PickHost(hostname, enum.DatabaseSocket)
		if err != nil {
			return err
		}
		hostname = pickedHost.Hostname()

		// Let's read preferences from the config file
		pref, err := preference.Read()
		if err != nil {
			fmt.Println("WARNING: could not read preference file:", err)
		}
		socketPref := preference.NewDatabaseSocket(hostname)

		var suggestedDBName string

		dbName := dbNameFrom(args)
		if dbName == "" {
			suggestedSocket := pref.GetOrSuggestSocket(hostname, enum.DatabaseSocket)
			if preference.Found(suggestedSocket) {
				suggestedDBName = suggestedSocket.DatabaseName
				socketPref = suggestedSocket
			}
		}

		dbName, err = client.EnterDBName(dbName, suggestedDBName)
		if err != nil {
			return err
		}

		socketPref.DatabaseName = dbName
		socketPref.DatabaseClient = "mycli"
		pref.SetSocket(socketPref)

		_, _, crtPath, keyPath, port, err := client.GetOrgCert(hostname)
		if err != nil {
			return err
		}

		persistPreference := func() {
			// persist preference to json file
			if err == nil {
				if err := preference.Write(pref); err != nil {
					fmt.Println("WARNING: could not update preference file:", err)
				}
			}
		}
		// make sure we will persist preference on successful connection to socket
		defer persistPreference()
		client.OnInterruptDo(persistPreference)

		err = client.ExecCommand("mycli", []string{
			"-h", hostname,
			"-P", fmt.Sprint(port),
			"--ssl-cert", crtPath,
			"--ssl-key", keyPath,
			dbName,
		}...)
		return err
	},
}
