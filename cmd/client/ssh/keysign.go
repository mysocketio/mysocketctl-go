package ssh

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/mysocketio/mysocketctl-go/internal/client"
	"github.com/spf13/cobra"
)

// sshKeySignCmd represents the client ssh keysign command
var keySignCmd = &cobra.Command{
	Use:     "ssh-keysign",
	Aliases: []string{"ssh:keysign"},
	Short:   "Generate a short lived ssh certificate signed by mysocket",
	RunE: func(cmd *cobra.Command, args []string) error {
		if hostname == "" {
			return errors.New("empty hostname not allowed")
		}

		token, claims, err := client.MTLSLogin(hostname)
		if err != nil {
			return err
		}

		key := client.GenSSHKey(token, claims["socket_dns"].(string))

		// write public key
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to write ssh key: %w", err)
		}

		err = ioutil.WriteFile(fmt.Sprintf("%s/.ssh/%s-cert.pub", home, claims["socket_dns"].(string)), []byte(key.SSHCertSigned), 0600)
		if err != nil {
			return fmt.Errorf("failed to write ssh key: %w", err)
		}

		// Also write token, for future use
		tokenfile := client.MTLSTokenFile(hostname)
		f, err := os.Create(tokenfile)
		if err != nil {
			return fmt.Errorf("failed to create token: %w", err)
		}
		defer f.Close()

		if err := os.Chmod(tokenfile, 0600); err != nil {
			return fmt.Errorf("failed to write token: %w", err)
		}

		_, err = f.WriteString(fmt.Sprintf("%s\n", token))
		if err != nil {
			return fmt.Errorf("failed to write token: %w", err)
		}
		return nil
	},
}
