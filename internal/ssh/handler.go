package ssh

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	mysocketctlhttp "github.com/mysocketio/mysocketctl-go/internal/http"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/net/proxy"
)

const (
	defaultTimeout = 30 * time.Second
)

var (
	defaultKeyFiles = []string{"id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"}
)

type httpProxy struct {
	host     string
	haveAuth bool
	username string
	password string
	forward  proxy.Dialer
}

func sshServer() string {
	if os.Getenv("MYSOCKET_ENV") == "staging" {
		return "ssh.staging.mysocket.io"
	} else {
		return "ssh.mysocket.io"
	}
}

func getSshCert(userId string, socketID string, tunnelID string) (s ssh.Signer) {

	// First check if we already have a mysocket key pair

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Error: failed to get home dir: %v", err)
	}

	privateKeyFile := home + "/.mysocket"
	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		err := os.Mkdir(privateKeyFile, 0700)
		if err != nil {
			log.Fatalf("Error: could not create directory: %v", err)
		}
	}

	privateKeyFile = home + "/.mysocket/user_" + userId

	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		// Let's create a key pair
		//log.Println("create key for " + userId)

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("Error: failed to create ssh key: %v", err)
		}

		parsed, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			log.Fatalf("Error: failed to create ssh key: %v", err)
		}

		keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: parsed})
		err = ioutil.WriteFile(privateKeyFile, keyPem, 0600)
		if err != nil {
			log.Fatalf("Error: failed to write ssh key: %v", err)
		}
	}
	// Ok now let's load the key

	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		log.Fatalf("Error: failed to load private ssh key: %v", err)
	}
	// read private key from file
	keyContent, _ := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		log.Fatalf("Error: failed to load private ssh key: %v", err)
	}

	block, _ := pem.Decode(keyContent)
	if block == nil {
		log.Fatal("failed to decode PEM block containing public key")
	}

	//pkey, err := ssh.ParsePrivateKey(keyContent)
	pkey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("Error: failed to parse private ssh key")
	}

	// create public key
	pub, err := ssh.NewPublicKey(&pkey.PublicKey)
	if err != nil {
		log.Fatalf("Error: failed to create public ssh key: %v", err)
	}
	data := ssh.MarshalAuthorizedKey(pub)

	//post signing request
	signedCert := mysocketctlhttp.SshCsr{}
	newCsr := &mysocketctlhttp.SshCsr{
		SSHPublicKey: strings.TrimRight(string(data), "\n"),
	}
	//log.Println(newCsr)
	client, err := mysocketctlhttp.NewClient()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	//err = client.Request("POST", "socket/"+socketID+"/tunnel/"+tunnelID+"/signkey", &signedCert, newCsr)

	for i := 1; i <= 10; i++ {
		err = client.Request("POST", "socket/"+socketID+"/tunnel/"+tunnelID+"/signkey", &signedCert, newCsr)
		if err == nil {
			break
		}
		log.Println(fmt.Sprintf("Unable to get signed cert from API, will try again in %d seconds. Attempt %d of 10", 2*i, i))

		d := time.Duration(2*i) * time.Second
		time.Sleep(d)
	}
	if signedCert.SSHSignedCert == "" {
		log.Fatalf("Error: Unable to get signed key from Server")
	}

	certData := []byte(signedCert.SSHSignedCert)
	pubcert, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	cert, ok := pubcert.(*ssh.Certificate)
	if !ok {
		log.Fatalf("Error failed to cast to certificate: %v", err)
	}
	//log.Println(cert.ValidPrincipals[0])
	clientKey, _ := ssh.ParsePrivateKey(keyContent)
	certSigner, err := ssh.NewCertSigner(cert, clientKey)
	if err != nil {
		log.Fatalf("NewCertSigner: %v", err)
	}
	return certSigner
}

func SshConnect(userID string, socketID string, tunnelID string, port int, targethost string, identityFile string, proxyHost string, version string) error {
	tunnel, err := mysocketctlhttp.GetTunnel(socketID, tunnelID)

	if err != nil {
		log.Fatalf("error: %v", err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            userID,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         defaultTimeout,
		ClientVersion:   fmt.Sprintf("SSH-2.0-Mysocketctl-%s", version),
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

	// Start a thread that refreshes the token
	// refresh every hour, 3600secs
	go func() {
		for {
			time.Sleep(3600 * time.Second)
			_, err := mysocketctlhttp.RefreshLogin()
			if err != nil {
				fmt.Println(err)
			}
		}
	}()

	for {
		// Let's fetch a short lived signed cert from api.mysocket.io
		// We'll use that to authenticate. This returns a signer object.
		// for now we'll just add it to the signers list.
		// In future, this is the only auth method we should use.
		sshCert := getSshCert(userID, socketID, tunnelID)
		// If we got a cert, we use that for auth method. Otherwise use static keys
		if sshCert != nil {
			sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(sshCert)}
		} else if signers != nil {
			sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(signers...)}
		} else {
			log.Fatal("No ssh keys found for authenticating..")
		}

		fmt.Println("\nConnecting to Server: " + sshServer() + "\n")
		time.Sleep(1 * time.Second)

		/*

			serverConn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", mySocketSSHServer, 22), sshConfig)
			if err != nil {
				log.Printf("Dial INTO remote server error: %s", err)
				continue
			}
			defer serverConn.Close()
		*/

		// check Dialer
		proxyMatch, _ := regexp.Compile("^http(s)?://")
		var proxyDialer proxy.Dialer
		if proxyMatch.MatchString(proxyHost) {
			proxyURL, err := url.Parse(proxyHost)
			if err != nil {
				log.Fatalf("Invalid proxy URL: %s", err)
			}
			proxy.RegisterDialerType("http", newHttpProxy)
			proxy.RegisterDialerType("https", newHttpProxy)
			proxyDialer, _ = proxy.FromURL(proxyURL, proxy.Direct)
		} else {
			proxyDialer = proxy.Direct
		}

		remoteHost := net.JoinHostPort(sshServer(), "22")
		// Dial to host:port
		conn, err := proxyDialer.Dial("tcp", remoteHost)
		if err != nil {
			log.Printf("Dial INTO remote server error: %s", err)
			continue
		}

		sshCon, channel, req, err := ssh.NewClientConn(conn, remoteHost, sshConfig)
		if err != nil {
			log.Printf("Dial INTO remote server error: %s", err)
			continue
		}

		// Create *ssh.Client
		serverConn := ssh.NewClient(sshCon, channel, req)
		defer serverConn.Close()

		listener, err := serverConn.Listen("tcp", fmt.Sprintf("localhost:%d", tunnel.LocalPort))
		if err != nil {
			log.Printf("Listen open port ON remote server on port %d error: %s", tunnel.LocalPort, err)
			serverConn.Close()
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
					log.Printf("Tunnel Connection accept error: %v", err)
					return
				}

				go func() {
					local, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targethost, port))
					if err != nil {
						log.Printf("Dial INTO local service error: %s", err)
						return
					}

					go handleClient(client, local)
				}()
			}
		}()

		if err := session.Wait(); err != nil {
			log.Printf("ssh session error: %v", err)
			session.Close()
			listener.Close()
			serverConn.Close()
		}
		serverConn.Close()
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

func newHttpProxy(uri *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
	s := new(httpProxy)
	s.host = uri.Host
	s.forward = forward
	if uri.User != nil {
		s.haveAuth = true
		s.username = uri.User.Username()
		s.password, _ = uri.User.Password()
	}
	return s, nil
}

func (s *httpProxy) Dial(network, addr string) (net.Conn, error) {
	c, err := s.forward.Dial("tcp", s.host)
	if err != nil {
		return nil, err
	}

	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		c.Close()
		return nil, err
	}
	reqURL.Scheme = ""

	req, err := http.NewRequest("CONNECT", reqURL.String(), nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	req.Close = false
	if s.haveAuth {
		req.SetBasicAuth(s.username, s.password)
	}
	req.Header.Set("User-Agent", "Mysocketctl")

	err = req.Write(c)
	if err != nil {
		c.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		resp.Body.Close()
		c.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		c.Close()
		err = fmt.Errorf("connect server using proxy error, StatusCode [%d]", resp.StatusCode)
		return nil, err
	}

	return c, nil
}
