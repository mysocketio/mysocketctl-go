package ssh

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/moby/term"
	"github.com/mysocketio/mysocketctl-go/client/preference"
	"github.com/mysocketio/mysocketctl-go/internal/client"
	"github.com/mysocketio/mysocketctl-go/internal/enum"
	mysocketSSH "github.com/mysocketio/mysocketctl-go/internal/ssh"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var (
	hostname     string
	sshLoginName string
)

type HostDB struct {
	Hosts []Host `json:"hosts"`
}

type Host struct {
	DNSname    string    `json:"dnsname"`
	Username   string    `json:"username"`
	LastUsed   time.Time `json:"lastused"`
	SocketType string    `json:"sockettype"`
}

func AddCommandsTo(client *cobra.Command) {
	client.AddCommand(sshCmd)
	sshCmd.Flags().StringVarP(&hostname, "host", "", "", "The ssh mysocket target host")
	sshCmd.Flags().StringVarP(&sshLoginName, "username", "u", "", "Specifies the user to log in as on the remote machine(deprecated)")
	sshCmd.Flags().StringVarP(&sshLoginName, "login", "l", "", "Same as username, specifies the user login to use on remote machine")

	client.AddCommand(keySignCmd)
	keySignCmd.Flags().StringVarP(&hostname, "host", "", "", "The mysocket target host")
	keySignCmd.MarkFlagRequired("host")
}

// sshCmd represents the client ssh keysign command
var sshCmd = &cobra.Command{
	Use:               "ssh",
	Short:             "Connect to a mysocket ssh service",
	ValidArgsFunction: client.AutocompleteHost,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			hostnameSlice := strings.SplitN(args[0], "@", 2)
			switch len(hostnameSlice) {
			case 1:
				hostname = hostnameSlice[0]
			case 2:
				sshLoginName = hostnameSlice[0]
				hostname = hostnameSlice[1]
			}
		}

		pickedHost, err := client.PickHost(hostname, enum.SSHSocket, enum.TLSSocket)
		if err != nil {
			return err
		}
		hostname = pickedHost.Hostname()

		token, claims, err := client.MTLSLogin(hostname)
		if err != nil {
			return err
		}
		orgID := fmt.Sprint(claims["org_id"])

		pref, err := preference.Read()
		if err != nil {
			fmt.Println("WARNING: could not read preference file:", err)
		}
		socketPref := preference.NewSSHSocket(hostname)

		if sshLoginName == "" {
			suggestedSocket := pref.Socket(hostname)
			if preference.Found(suggestedSocket) {
				sshLoginName = suggestedSocket.Username
				socketPref = suggestedSocket
			} else {
				suggestedSocket = pref.SuggestSocket(hostname, enum.SSHSocket)
				if preference.Found(suggestedSocket) {
					sshLoginName = suggestedSocket.Username
					socketPref = suggestedSocket
				}
				if err = survey.AskOne(&survey.Input{
					Message: "SSH username:",
					Default: sshLoginName,
				}, &sshLoginName); err != nil {
					return errors.New("failed to get login/username, empty login not allowed")
				}
			}
		}

		// Now we should have the login name, so lets write back the data to the preference file
		socketPref.Username = sshLoginName
		pref.SetSocket(socketPref)

		sshCert, err := client.GenSSHKey(token, orgID, hostname)
		if err != nil {
			return fmt.Errorf("unable to create ssh key: %w", err)
		}

		cert, key, _, _, port, err := client.GetOrgCert(hostname)
		if err != nil {
			log.Fatalf("failed to get certificate: %v", err.Error())
		}

		certificate := tls.Certificate{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key,
		}

		config := tls.Config{Certificates: []tls.Certificate{certificate}, InsecureSkipVerify: true, ServerName: hostname}
		conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", hostname, port), &config)
		if err != nil {
			return fmt.Errorf("failed to connect to %s:%d: %w", hostname, port, err)
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to write ssh key: %w", err)
		}

		buffer, err := ioutil.ReadFile(fmt.Sprintf("%s/.ssh/%s", home, claims["org_id"]))
		if err != nil {
			return err
		}

		k, err := ssh.ParsePrivateKey(buffer)
		if err != nil {
			return err
		}

		certData := []byte(sshCert.SSHCertSigned)
		pubcert, _, _, _, err := ssh.ParseAuthorizedKey(certData)
		if err != nil {
			return err
		}
		cert1, ok := pubcert.(*ssh.Certificate)
		if !ok {
			return fmt.Errorf("failed to cast to certificate: %w", err)
		}

		certSigner, err := ssh.NewCertSigner(cert1, k)
		if err != nil {
			return fmt.Errorf("NewCertSigner: %w", err)
		}

		sshConfig := &ssh.ClientConfig{
			User:            sshLoginName,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         10 * time.Second,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		}

		fmt.Printf("\nConnecting to Server: %s:%d as %s \n", hostname, port, sshLoginName)
		serverConn, chans, reqs, err := ssh.NewClientConn(conn, hostname, sshConfig)
		if err != nil {
			return fmt.Errorf("dial into remote server error: %s %+v", err, conn.ConnectionState())
		}
		defer serverConn.Close()

		sshClient := ssh.NewClient(serverConn, chans, reqs)

		session, err := sshClient.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create session: %w", err)
		}
		defer session.Close()

		// persist logged in username
		if err := preference.Write(pref); err != nil {
			fmt.Println("WARNING: could not update preference file:", err)
		}

		fd := os.Stdin.Fd()

		var termWidth, termHeight = 80, 24

		if term.IsTerminal(fd) {
			oldState, err := term.MakeRaw(fd)
			if err != nil {
				log.Fatalf("%s", err)
			}

			defer term.RestoreTerminal(fd, oldState)

			winsize, err := term.GetWinsize(fd)
			if err == nil {
				termWidth = int(winsize.Width)
				termHeight = int(winsize.Height)
			}
		}

		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}

		term := os.Getenv("TERM")
		if term == "" {
			term = "xterm-256color"
		}

		if err := session.RequestPty(term, termHeight, termWidth, modes); err != nil {
			return fmt.Errorf("session xterm: %w", err)
		}

		go client.MonWinCh(session, os.Stdout.Fd())

		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
		session.Stdin = os.Stdin

		if err := session.Shell(); err != nil {
			return fmt.Errorf("session shell: %w", err)
		}

		done := make(chan bool, 1)
		defer func() { done <- true }()

		go mysocketSSH.KeepAlive(sshClient, done)
		if err := session.Wait(); err != nil {
			// gracefully handle ssh.ExitMissingError. It's returned if a session is torn down cleanly,
			// but the server sends no confirmation of the exit status
			if !errors.Is(err, new(ssh.ExitMissingError)) {
				return err
			}
		}
		return nil
	},
}
