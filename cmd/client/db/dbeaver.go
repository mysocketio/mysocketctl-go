package db

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/mysocketio/mysocketctl-go/internal/client"
	"github.com/spf13/cobra"
)

var dbeaverCmd = &cobra.Command{
	Use:   "db:dbeaver",
	Short: "Connect to a database socket with dbeaver",
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			dbName string
			err    error
		)
		hostname, dbName, err = client.PickHostAndEnterDBName(hostname, dbNameFrom(args))
		if err != nil {
			return err
		}

		_, claims, err := client.MTLSLogin(hostname)
		if err != nil {
			return err
		}

		orgID := fmt.Sprint(claims["org_id"])
		cert, key, _, _, socketPort, err := client.GetOrgCert(hostname)
		if err != nil {
			return err
		}

		keyStore, keyStorePassword, _ := client.CertToKeyStore(cert, key)
		defer client.Zeroing(keyStorePassword)

		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home dir : %w", err)
		}
		keyStorePath := filepath.Join(home, ".mysocketio", orgID+".jks")
		client.WriteKeyStore(keyStore, keyStorePath, keyStorePassword)

		// for more about jdbc driver properties, see:
		// https://dev.mysql.com/doc/connector-j/5.1/en/connector-j-connp-props-security.html
		// also see this page for connection parameters:
		// https://github.com/dbeaver/dbeaver/wiki/Command-Line#connection-parameters
		params := []string{
			"host=" + hostname,
			"port=" + fmt.Sprint(socketPort),
			"database=" + dbName,
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

		fmt.Println("Starting up DBeaver...")
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
