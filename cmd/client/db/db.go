package db

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/mysocketio/mysocketctl-go/internal/client"
	"github.com/mysocketio/mysocketctl-go/internal/client/mysqlworkbench"
	"github.com/spf13/cobra"
)

var (
	hostname string
	port     int
)

func AddCommandsTo(client *cobra.Command) {
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

var mysqlCmd = &cobra.Command{
	Use:   "db:mysql",
	Short: "Connect to a database socket with MySQL client",
	RunE: func(cmd *cobra.Command, args []string) error {
		crtPath, keyPath, port, err := client.FetchCertAndReturnPaths(hostname, port)
		if err != nil {
			return err
		}
		return client.ExecCommand("mysql", []string{
			"-h", hostname,
			"-P", fmt.Sprint(port),
			"--protocol", "TCP",
			"--ssl-cert", crtPath,
			"--ssl-key", keyPath,
			dbNameFrom(args),
		}...)
	},
}

var mycliCmd = &cobra.Command{
	Use:   "db:mycli",
	Short: "Connect to a database socket with mycli client",
	RunE: func(cmd *cobra.Command, args []string) error {
		crtPath, keyPath, port, err := client.FetchCertAndReturnPaths(hostname, port)
		if err != nil {
			return err
		}
		return client.ExecCommand("mycli", []string{
			"-h", hostname,
			"-P", fmt.Sprint(port),
			"--ssl-cert", crtPath,
			"--ssl-key", keyPath,
			dbNameFrom(args),
		}...)
	},
}

var mysqlWorkbenchCmd = &cobra.Command{
	Use:   "db:mysqlworkbench",
	Short: "Connect to a database socket with MySQL Workbench",
	RunE: func(cmd *cobra.Command, args []string) error {
		crtPath, keyPath, port, err := client.FetchCertAndReturnPaths(hostname, port)
		if err != nil {
			return err
		}

		// for more info about mysql workbench command line options and config files, see:
		// https://dev.mysql.com/doc/workbench/en/wb-command-line-options.html
		// https://dev.mysql.com/doc/workbench/en/wb-configuring-files.html
		xmlDoc, err := mysqlworkbench.ConnectionsXML(hostname, port, crtPath, keyPath, dbNameFrom(args))
		if err != nil {
			return err
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("Error: failed to get home dir : %w", err)
		}
		// create dir if not exists
		configPath := filepath.Join(home, ".mysocketio", "mysqlworkbench")
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			if err := os.Mkdir(configPath, 0700); err != nil {
				return fmt.Errorf("Error: failed to create directory %s : %w", configPath, err)
			}
		}
		xmlPath := filepath.Join(configPath, "connections.xml")
		if err = ioutil.WriteFile(xmlPath, []byte(xmlDoc), 0600); err != nil {
			return fmt.Errorf("Error: failed writing MySQL Workbench connections.xml file: %w", err)
		}

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

var dbeaverCmd = &cobra.Command{
	Use:   "db:dbeaver",
	Short: "Connect to a database socket with dbeaver",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, claims, err := client.MTLSLogin(hostname)
		if err != nil {
			return err
		}

		socketDNS := fmt.Sprint(claims["socket_dns"])
		userEmail := fmt.Sprint(claims["user_email"])

		cert := client.GetCert(token, socketDNS, userEmail)
		keyStore, keyStorePassword, err := client.CertToKeyStore(cert)
		defer client.Zeroing(keyStorePassword)

		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("Error: failed to get home dir : %w", err)
		}
		keyStorePath := filepath.Join(home, ".mysocketio", socketDNS+".jks")
		client.WriteKeyStore(keyStore, keyStorePath, keyStorePassword)

		socketPort, err := client.GetSocketPortFrom(claims, port)
		if err != nil {
			return err
		}

		// for more about jdbc driver properties, see:
		// https://dev.mysql.com/doc/connector-j/5.1/en/connector-j-connp-props-security.html
		// also see this page for connection parameters:
		// https://github.com/dbeaver/dbeaver/wiki/Command-Line#connection-parameters
		params := []string{
			"host=" + hostname,
			"port=" + fmt.Sprint(socketPort),
			"database=" + dbNameFrom(args),
			"prop.clientCertificateKeyStoreUrl=file:" + keyStorePath,
			"prop.clientCertificateKeyStorePassword=" + string(keyStorePassword),
			"driver=mysql5",
			"user=placeholder",
			"savePassword=true", // does not ask user for a password on connection
			"openConsole=true",  // opens the SQL console for this database (also sets connect to true)
			"prop.useSSL=true",
			"prop.verifyServerCertificate=false",
			"prop.requireSSL=false",
		}
		conn := strings.Join(params, "|")

		switch runtime.GOOS {
		case "darwin":
			return client.ExecCommand("open", "-a", "dbeaver", "--args", "-con", conn)
		case "windows":
			return client.ExecCommand("cmd", "/C", "start", "", "dbeaver.exe", "-con", conn)
		default:
			return client.ExecCommand("dbeaver", "-con", conn)
		}
	},
}

func dbNameFrom(args []string) string {
	var dbName string
	if len(args) > 0 {
		dbName = args[0]
	}
	return dbName
}
