package db

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"

	"github.com/mysocketio/mysocketctl-go/client/preference"
	"github.com/mysocketio/mysocketctl-go/internal/client"
	"github.com/mysocketio/mysocketctl-go/internal/client/mysqlworkbench"
	"github.com/mysocketio/mysocketctl-go/internal/enum"
	"github.com/spf13/cobra"
)

var mysqlWorkbenchCmd = &cobra.Command{
	Use:   "db:mysqlworkbench",
	Short: "Connect to a database socket with MySQL Workbench",
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
		socketPref.DatabaseClient = "mysqlworkbench"
		pref.SetSocket(socketPref)

		_, _, crtPath, keyPath, port, err := client.GetOrgCert(hostname)
		if err != nil {
			return err
		}

		// for more info about mysql workbench command line options and config files, see:
		// https://dev.mysql.com/doc/workbench/en/wb-command-line-options.html
		// https://dev.mysql.com/doc/workbench/en/wb-configuring-files.html
		xmlDoc, err := mysqlworkbench.ConnectionsXML(hostname, port, crtPath, keyPath, dbName)
		if err != nil {
			return err
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home dir : %w", err)
		}
		// create dir if not exists
		configPath := filepath.Join(home, ".mysocketio", "mysqlworkbench")
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			if err := os.Mkdir(configPath, 0700); err != nil {
				return fmt.Errorf("failed to create directory %s : %w", configPath, err)
			}
		}
		xmlPath := filepath.Join(configPath, "connections.xml")
		if err = ioutil.WriteFile(xmlPath, []byte(xmlDoc), 0600); err != nil {
			return fmt.Errorf("failed writing MySQL Workbench connections.xml file: %w", err)
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

		fmt.Println("Starting up MySQL Workbench...")
		switch runtime.GOOS {
		case "darwin":
			err = client.ExecCommand("open", "-a", "MySQLWorkbench", "--args", "--configdir", configPath)
		case "windows":
			err = client.ExecCommand("cmd", "/C", "start", "", "mysqlworkbench.exe", "--configdir", configPath)
		default:
			err = client.ExecCommand("mysql-workbench", "--configdir", configPath)
		}
		return err
	},
}
