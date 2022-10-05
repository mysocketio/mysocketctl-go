package db

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/mysocketio/mysocketctl-go/client/preference"
	"github.com/mysocketio/mysocketctl-go/internal/client"
	"github.com/mysocketio/mysocketctl-go/internal/enum"
	"github.com/spf13/cobra"
)

var dbeaverCmd = &cobra.Command{
	Use:   "db:dbeaver",
	Short: "Connect to a database socket with dbeaver",
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
		socketPref.DatabaseClient = "dbeaver"
		pref.SetSocket(socketPref)

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
		_, claims, err := client.MTLSLogin(hostname)
		if err != nil {
			return err
		}
		orgID := fmt.Sprint(claims["org_id"])
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
			"driver=mariadb",
			"user=placeholder",
			"savePassword=true", // does not ask user for a password on connection
			"openConsole=true",  // opens the SQL console for this database (also sets connect to true)
			"prop.useSSL=true",
			"prop.verifyServerCertificate=false",
			"prop.requireSSL=false",
		}
		if pickedHost.PrivateSocket {
			// NOTE: temp fix - do this to bypass the error that complains the mismatch between
			//       private hostname and the CN in certificate (*.edge.mysocket.io)
			params = append(params, "prop.disableSslHostnameVerification=true")
		}
		conn := strings.Join(params, "|")

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

		fmt.Println("Starting up DBeaver...")
		switch runtime.GOOS {
		case "darwin":
			err = client.ExecCommand("open", "-a", "dbeaver", "--args", "-con", conn)
		case "windows":
			conn = "\"" + conn + "\""
			err = client.ExecCommand("cmd", "/C", "start", "", "c:\\Program Files\\DBeaver\\dbeaver.exe", "-con", conn)
		default:
			err = client.ExecCommand("dbeaver", "-con", conn)
		}
		return err
	},
}
