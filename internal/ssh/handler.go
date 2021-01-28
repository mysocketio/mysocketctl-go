package ssh

import (
	"fmt"
	"github.com/mysocketio/mysocketctl-go/internal/http"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"
)

const (
	mySocketSSHServer = "ssh.mysocket.io"
	defaultTimeout    = 30 * time.Second
)

var (
	defaultKeyFiles = []string{"id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"}
)

func SshConnect(userID string, socketID string, tunnelID string, port int, targethost string, identityFile string) error {
	tunnel, err := http.GetTunnel(socketID, tunnelID)

	if err != nil {
		log.Fatalf("error: %v", err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            userID,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         defaultTimeout,
	}
	var keyFiles []string
	var signers []ssh.Signer

	if identityFile != "" {
		f := []string{identityFile}
		if auth, err := authWithPrivateKeys(f, true); err == nil {
			signers = append(signers, auth...)
		}
	}

	if auth, err := authWithAgent(); err == nil {
		signers = append(signers, auth...)
	}

	home, err := os.UserHomeDir()
	if err == nil {
		for _, k := range defaultKeyFiles {
			f := home + "/.ssh/" + k
			if _, err := os.Stat(f); err == nil {
				keyFiles = append(keyFiles, f)
			}
		}
	}

	if auth, err := authWithPrivateKeys(keyFiles, false); err == nil {
		signers = append(signers, auth...)
	}

	if signers != nil {
		sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeys(signers...))
	}

	fmt.Println("\nConnecting to Server: " + mySocketSSHServer + "\n")

	for {
		time.Sleep(2 * time.Second)
		serverConn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", mySocketSSHServer, 22), sshConfig)
		if err != nil {
			log.Printf("Dial INTO remote server error: %s", err)
			continue
		}

		listener, err := serverConn.Listen("tcp", fmt.Sprintf("localhost:%d", tunnel.LocalPort))
		if err != nil {
			log.Printf("Listen open port ON remote server on port %d error: %s", tunnel.LocalPort, err)
			continue
		}
		defer listener.Close()

		session, err := serverConn.NewSession()
		if err != nil {
			log.Printf("Failed to create session: %v", err)
			continue
		}
		defer session.Close()

		session.Stdout = os.Stdout
		modes := ssh.TerminalModes{}

		if err := session.RequestPty("xterm-256color", 80, 40, modes); err != nil {
			log.Printf("request for pseudo terminal failed: %s", err)
			continue
		}

		if err := session.Shell(); err != nil {
			log.Print(err)
			continue
		}

		go func() {
			for {
				client, err := listener.Accept()
				if err != nil {
					log.Printf("SSH accept error: %v", err)
					return
				}

				go func() {
					local, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targethost, port))
					if err != nil {
						log.Printf("Dial INTO local service error: %s", err)
						return
					}

					//go ioCopy(client, local)
					//go ioCopy(local, client)
					go handleClient(client, local)
				}()
			}
		}()

		if err := session.Wait(); err != nil {
			log.Print(err)
			continue
		}
	}
}

func handleClient(client net.Conn, remote net.Conn) {
	defer client.Close()
	chDone := make(chan bool)

	// Start remote -> local data transfer
	go func() {
		_, err := io.Copy(client, remote)
		if err != nil {
			log.Println(fmt.Sprintf("error while copy remote->local: %s", err))
		}
		chDone <- true
	}()

	// Start local -> remote data transfer
	go func() {
		_, err := io.Copy(remote, client)
		if err != nil {
			log.Println(fmt.Sprintf("error while copy local->remote: %s", err))
		}
		chDone <- true
	}()

	<-chDone
}

func ioCopy(dst io.Writer, src io.Reader) {
	if _, err := io.Copy(dst, src); err != nil {
		log.Printf("io.Copy failed: %v", err)
	}
}

func authWithPrivateKeys(keyFiles []string, fatalOnError bool) ([]ssh.Signer, error) {
	var signers []ssh.Signer

	for _, file := range keyFiles {

		b, err := ioutil.ReadFile(file)
		if err != nil {
			if fatalOnError {
				log.Fatalln(fmt.Sprintf("Cannot read SSH key file %s (%v)", file, err.Error()))
			} else {
				continue
			}
		}
		signer, err := ssh.ParsePrivateKey(b)
		if err != nil {
			if fatalOnError {
				log.Fatalln(fmt.Sprintf("Cannot read SSH key file %s (%v)", file, err.Error()))
			} else {
				continue
			}
		}
		signers = append(signers, signer)
	}

	return signers, nil
}

func authWithAgent() ([]ssh.Signer, error) {
	if os.Getenv("SSH_AUTH_SOCK") != "" {
		sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
		if err == nil {
			agentSigners, _ := agent.NewClient(sshAgent).Signers()
			return agentSigners, nil
		}
	}

	return nil, nil
}
