package ssh

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/mysocketio/mysocketctl-go/internal/client"
	"github.com/spf13/cobra"
)

// sshKeySignCmd represents the client ssh keysign command
var keySignCmd = &cobra.Command{
	Use:     "ssh-keysign",
	Aliases: []string{"ssh:keysign"},
	Short:   "Generate a ssh certificate signed by mysocket",
	RunE: func(cmd *cobra.Command, args []string) error {
		if hostname == "" {
			return errors.New("empty hostname not allowed")
		}

		token, claims, err := client.MTLSLogin(hostname)
		if err != nil {
			return err
		}

		orgID := claims["org_id"].(string)

		_, err = client.GenSSHKey(token, orgID, hostname)

		if err != nil {
			log.Fatalln(err)
		}

		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("failed to write ssh key: %v", err)
		}

		socketSshCertPath := filepath.Join(home, ".ssh", fmt.Sprintf("%s-cert.pub", hostname))
		socketSshKeyPath := filepath.Join(home, ".ssh", hostname)

		var createSshCertLink, createSshKeyLink bool

		fi, err := os.Lstat(socketSshCertPath)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Printf("failed to read link: %v", err)
			} else {
				createSshCertLink = true
			}
		} else {
			if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
				os.Remove(socketSshCertPath)
				createSshCertLink = true
			}
		}

		fi, err = os.Lstat(socketSshKeyPath)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Printf("failed to read link: %v", err)
			} else {
				createSshKeyLink = true
			}
		} else {
			if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
				os.Remove(socketSshKeyPath)
				createSshKeyLink = true
			}
		}

		orgSshCertPath := fmt.Sprintf("%s-cert.pub", orgID)
		orgSshKeyPath := orgID

		if createSshCertLink {
			err = os.Symlink(orgSshCertPath, socketSshCertPath)
			if err != nil {
				log.Printf("failed to link ssh cert: %s", err)
			}
		}

		if createSshKeyLink {
			err = os.Symlink(orgSshKeyPath, socketSshKeyPath)
			if err != nil {
				log.Printf("failed to link ssh key: %s", err)
			}
		}

		return nil
	},
}
