package db

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"

	"github.com/mysocketio/mysocketctl-go/internal/client"
	"github.com/mysocketio/mysocketctl-go/internal/client/mysqlworkbench"
	"github.com/spf13/cobra"
)

var mysqlWorkbenchCmd = &cobra.Command{
	Use:   "db:mysqlworkbench",
	Short: "Connect to a database socket with MySQL Workbench",
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			dbName string
			err    error
		)
		hostname, dbName, err = client.PickHostAndEnterDBName(hostname, dbNameFrom(args))
		if err != nil {
			return err
		}
		crtPath, keyPath, port, err := client.FetchCertAndReturnPaths(hostname, port)
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

		fmt.Println("Starting up MySQL Workbench...")
		switch runtime.GOOS {
		case "darwin":
			return client.ExecCommand("open", "-a", "MySQLWorkbench", "--args", "--configdir", configPath)
		case "windows":
			return client.ExecCommand("cmd", "/C", "start", "", "mysqlworkbench.exe", "--configdir", configPath)
		default:
			return client.ExecCommand("mysql-workbench", "--configdir", configPath)
		}
	},
}
