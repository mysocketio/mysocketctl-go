package ssh

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/moby/term"
	"github.com/mysocketio/mysocketctl-go/internal/client"
	"github.com/mysocketio/mysocketctl-go/internal/enum"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var (
	hostname string
	username string
)

func AddCommandsTo(client *cobra.Command) {
	client.AddCommand(sshCmd)
	sshCmd.Flags().StringVarP(&hostname, "host", "", "", "The ssh mysocket target host")
	sshCmd.Flags().StringVarP(&username, "username", "", "", "Specifies the user to log in as on the remote machine")
	sshCmd.MarkFlagRequired("username")

	client.AddCommand(keySignCmd)
	keySignCmd.Flags().StringVarP(&hostname, "host", "", "", "The mysocket target host")
	keySignCmd.MarkFlagRequired("host")
}

// sshCmd represents the client ssh keysign command
var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Connect to a mysocket ssh service",
	RunE: func(cmd *cobra.Command, args []string) error {
		if username == "" {
			return errors.New("empty username not allowed")
		}

		hostname, err := client.PickHost(hostname, enum.SSHSocket, enum.TLSSocket)
		if err != nil {
			return err
		}

		token, claims, err := client.MTLSLogin(hostname)
		if err != nil {
			return err
		}

		socketDNS := fmt.Sprint(claims["socket_dns"])
		userEmail := fmt.Sprint(claims["user_email"])

		cert := client.GetCert(token, socketDNS, userEmail)
		if _, _, err := client.WriteCertToFile(cert, socketDNS); err != nil {
			return err
		}

		port, err := client.GetSocketPortFrom(claims, 0)
		if err != nil {
			return err
		}

		sshCert := client.GenSSHKey(token, claims["socket_dns"].(string))
		certificate, err := tls.X509KeyPair([]byte(cert.Certificate), []byte(cert.PrivateKey))
		if err != nil {
			return fmt.Errorf("unable to load certificate: %w", err)
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

		buffer, err := ioutil.ReadFile(fmt.Sprintf("%s/.ssh/%s", home, hostname))
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
			User:            username,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         10 * time.Second,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		}

		fmt.Printf("\nConnecting to Server: %s:%d\n", hostname, port)
		serverConn, chans, reqs, err := ssh.NewClientConn(conn, hostname, sshConfig)
		if err != nil {
			return fmt.Errorf("Dial INTO remote server error: %s %+v", err, conn.ConnectionState())
		}
		defer serverConn.Close()

		sshClient := ssh.NewClient(serverConn, chans, reqs)

		session, err := sshClient.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create session: %w", err)
		}
		defer session.Close()

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

		/*
			        go func() {
						sigs := make(chan os.Signal, 1)
						signal.Notify(sigs, syscall.SIGWINCH)
						defer signal.Stop(sigs)
						// resize the tty if any signals received
						for range sigs {
							session.SendRequest("window-change", false, termSize(os.Stdout.Fd()))
						}
					}()
		*/
		go client.MonWinCh(session, os.Stdout.Fd())

		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
		session.Stdin = os.Stdin

		if err := session.Shell(); err != nil {
			return fmt.Errorf("session shell: %w", err)
		}

		/*
			if err := session.Wait(); err != nil {
				if e, ok := err.(*ssh.ExitError); ok {
					switch e.ExitStatus() {
					case 130:
						os.Exit(0)
					}
				}
				log.Fatalf("ssh: %s", err)
			}
		*/
		return session.Wait()
	},
}
