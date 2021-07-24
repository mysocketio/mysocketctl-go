/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/docker/docker/pkg/term"
	"github.com/txn2/txeh"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/shirou/gopsutil/process"

	mhttp "github.com/mysocketio/mysocketctl-go/internal/http"
	"github.com/spf13/cobra"
	"github.com/takama/daemon"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
)

const (
	mysocket_mtls_url   = "https://mtls.edge.mysocket.io"
	mysocket_api_url    = "https://api.mysocket.io"
	mysocket_succes_url = "https://mysocket.io/succes-message/"
	mysocket_fail_url   = "https://mysocket.io/fail-message/"

	// for Service
	service_name        = "mysocket_service"
	service_description = "MySocket.io Service"
)

type Service struct {
	daemon.Daemon
}

var stdlog, errlog *log.Logger

//   dependencies that are NOT required by the service, but might be used
var service_dependencies = []string{}

type CertificateSigningRequest struct {
	Csr string `json:"csr"`
}

type CertificateResponse struct {
	PrivateKey  string `json:"client_private_key,omitempty"`
	Certificate string `json:"client_certificate,omitempty"`
}

type SshSignRequest struct {
	SshPublicKey string `json:"ssh_public_key"`
}

type SshSignResponse struct {
	SshCertSigned string `json:"signed_ssh_cert"`
}

// clientCmd represents the client command
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Client commands",
}

// clientSshCmd represents the client ssh keysign command
var clientSshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Connect to a mysocket ssh service",
	Run: func(cmd *cobra.Command, args []string) {
		if hostname == "" {
			log.Fatalf("error: empty hostname not allowed")
		}

		if username == "" {
			log.Fatalf("error: empty username not allowed")
		}

		listener, err := net.Listen("tcp", "localhost:")
		if err != nil {
			log.Fatalln("Error: Unable to start local http listener.")
		}

		local_port := listener.Addr().(*net.TCPAddr).Port
		url := fmt.Sprintf("%s/mtls-ca/socket/%s/auth?port=%d", mysocket_mtls_url, hostname, local_port)
		token := launch(url, listener)

		jwt_token, err := jwt.Parse(token, nil)
		if jwt_token == nil {
			log.Fatalf("couldn't parse token: %v", err.Error())
		}

		claims := jwt_token.Claims.(jwt.MapClaims)
		if _, ok := claims["user_email"]; ok {
		} else {
			log.Fatalf("Can't find claim for user_email")
		}

		if _, ok := claims["socket_dns"]; ok {
		} else {
			log.Fatalf("Can't find claim for socket_dns")
		}

		var sshCert *SshSignResponse
		sshCert = genSshKey(token, claims["socket_dns"].(string))

		var cert *CertificateResponse
		cert = getCert(token, claims["socket_dns"].(string), claims["user_email"].(string))

		certificate, err := tls.X509KeyPair([]byte(cert.Certificate), []byte(cert.PrivateKey))
		if err != nil {
			log.Fatalf("Error: unable to load certificate: %s", err)
		}

		// If user didnt set port using --port, then get it from jwt token
		if port == 0 {
			if _, ok := claims["socket_port"]; ok {
			} else {
				log.Fatalf("Can't find claim for socket_port")
			}
			port = int(claims["socket_port"].(float64))

			if port == 0 {
				log.Fatalf("Error: Unable to get tls port from token")
			}

		}
		config := tls.Config{Certificates: []tls.Certificate{certificate}, InsecureSkipVerify: true, ServerName: hostname}
		conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", hostname, port), &config)
		if err != nil {
			log.Fatalf("failed to connect to %s:%d: %v", hostname, port, err.Error())
		}

		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Error: failed to write ssh key: %v", err)
		}

		buffer, err := ioutil.ReadFile(fmt.Sprintf("%s/.ssh/%s", home, hostname))
		if err != nil {
			log.Fatalf("Error: %s", err)
		}

		k, err := ssh.ParsePrivateKey(buffer)
		if err != nil {
			log.Fatalf("Error: %s", err)
		}

		certData := []byte(sshCert.SshCertSigned)
		pubcert, _, _, _, err := ssh.ParseAuthorizedKey(certData)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		cert1, ok := pubcert.(*ssh.Certificate)

		if !ok {
			log.Fatalf("Error failed to cast to certificate: %v", err)
		}

		certSigner, err := ssh.NewCertSigner(cert1, k)
		if err != nil {
			log.Fatalf("NewCertSigner: %v", err)
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
			log.Fatalf("Dial INTO remote server error: %s %+v", err, conn.ConnectionState())
		}
		defer serverConn.Close()

		client := ssh.NewClient(serverConn, chans, reqs)

		session, err := client.NewSession()
		if err != nil {
			log.Fatalf("Failed to create session: " + err.Error())
		}
		defer session.Close()

		fd := os.Stdin.Fd()

		var (
			termWidth, termHeight = 80, 24
		)

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
			log.Fatalf("session xterm: %s", err)
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
		go monWinCh(session, os.Stdout.Fd())

		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
		session.Stdin = os.Stdin

		if err := session.Shell(); err != nil {
			log.Fatalf("session shell: %s", err)
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
		session.Wait()

	},
}

// clientSshKeySignCmd represents the client ssh keysign command
var clientSshKeySignCmd = &cobra.Command{
	Use:   "ssh-keysign",
	Short: "Generate a short lived ssh certificate signed by mysocket",
	Run: func(cmd *cobra.Command, args []string) {
		if hostname == "" {
			log.Fatalf("error: empty hostname not allowed")
		}

		listener, err := net.Listen("tcp", "localhost:")
		if err != nil {
			log.Fatalln("Error: Unable to start local http listener.")
		}

		local_port := listener.Addr().(*net.TCPAddr).Port
		url := fmt.Sprintf("%s/mtls-ca/socket/%s/auth?port=%d", mysocket_mtls_url, hostname, local_port)
		token := launch(url, listener)

		jwt_token, err := jwt.Parse(token, nil)
		if jwt_token == nil {
			log.Fatalf("couldn't parse token: %v", err.Error())
		}

		claims := jwt_token.Claims.(jwt.MapClaims)
		if _, ok := claims["user_email"]; ok {
		} else {
			log.Fatalf("Can't find claim for user_email")
		}

		if _, ok := claims["socket_dns"]; ok {
		} else {
			log.Fatalf("Can't find claim for socket_dns")
		}

		var key *SshSignResponse
		key = genSshKey(token, claims["socket_dns"].(string))

		// write public key
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Error: failed to write ssh key: %v", err)
		}

		err = ioutil.WriteFile(fmt.Sprintf("%s/.ssh/%s-cert.pub", home, claims["socket_dns"].(string)), []byte(key.SshCertSigned), 0600)
		if err != nil {
			log.Fatalf("Error: failed to write ssh key: %v", err)
		}

		// Also write token, for future use
		tokenfile := mtls_tokenfile(hostname)
		f, _ := os.Create(tokenfile)

		if err != nil {
			log.Fatalf("Error: failed to create token: %v", err)
		}

		if err := os.Chmod(tokenfile, 0600); err != nil {
			log.Fatalf("Error: failed to write token: %v", err)
		}

		defer f.Close()
		_, err = f.WriteString(fmt.Sprintf("%s\n", token))
		if err != nil {
			log.Fatalf("Error: failed to write token: %v", err)
		}

		return
	},
}

// clientTlsCmd represents the client tls command
var clientTlsCmd = &cobra.Command{
	Use:   "tls",
	Short: "Connect to a mysocket TLS protected socket",
	Run: func(cmd *cobra.Command, args []string) {
		if hostname == "" {
			log.Fatalf("error: empty hostname not allowed")
		}

		//Check for  hostname checking in *.mysocket-dummy
		// This may be used by ssh users
		// if so strip that
		substr := "(.*).mysocket-dummy$"
		r, _ := regexp.Compile(substr)
		match := r.FindStringSubmatch(hostname)
		if match != nil {
			hostname = match[1]
		}

		// Check if we already have a valid token
		token_content := ""

		tokenfile := mtls_tokenfile(hostname)
		if _, err := os.Stat(tokenfile); os.IsNotExist(err) {
			// Does not exist
		} else {
			// read token from file
			content, _ := ioutil.ReadFile(tokenfile)
			if err == nil {
				tokenString := strings.TrimRight(string(content), "\n")
				tmp_jwt_token, _ := jwt.Parse(tokenString, nil)
				if tmp_jwt_token != nil {

					claims := tmp_jwt_token.Claims.(jwt.MapClaims)
					exp := int64(claims["exp"].(float64))
					//  subtract 10secs from token, for expected work time
					//  If token time is larger then current time we're good
					if exp-10 > time.Now().Unix() {
						token_content = tokenString
					}
				}
			}
		}

		if token_content == "" {

			listener, err := net.Listen("tcp", "localhost:")
			if err != nil {
				log.Fatalln("Error: Unable to start local http listener.")
			}

			local_port := listener.Addr().(*net.TCPAddr).Port
			url := fmt.Sprintf("%s/mtls-ca/socket/%s/auth?port=%d", mysocket_mtls_url, hostname, local_port)
			token_content = launch(url, listener)
		}

		jwt_token, err := jwt.Parse(token_content, nil)
		if jwt_token == nil {
			log.Fatalf("couldn't parse token: %v", err.Error())
		}

		claims := jwt_token.Claims.(jwt.MapClaims)
		if _, ok := claims["user_email"]; ok {
		} else {
			log.Fatalf("Can't find claim for user_email")
		}

		if _, ok := claims["socket_dns"]; ok {
		} else {
			log.Fatalf("Can't find claim for socket_dns")
		}

		var cert *CertificateResponse
		if token_content != "" {
			cert = getCert(token_content, claims["socket_dns"].(string), claims["user_email"].(string))
		} else {
			log.Fatalln("Error: Login failed")
		}

		certificate, err := tls.X509KeyPair([]byte(cert.Certificate), []byte(cert.PrivateKey))
		if err != nil {
			log.Fatalf("Error: unable to load certificate: %s", err)
		}

		// If user didnt set port using --port, then get it from jwt token
		if port == 0 {
			if _, ok := claims["socket_port"]; ok {
			} else {
				log.Fatalf("Can't find claim for socket_port")
			}
			port = int(claims["socket_port"].(float64))

			if port == 0 {
				log.Fatalf("Error: Unable to get tls port from token")
			}

		}
		config := tls.Config{Certificates: []tls.Certificate{certificate}, InsecureSkipVerify: true, ServerName: hostname}
		conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", hostname, port), &config)
		if err != nil {
			log.Fatalf("failed to connect: %v", err.Error())
		}

		tcp_con_handle(conn)

	},
}

// clientLoginCmd represents the client login DNS command
var clientLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login and get API token so service can authenticate",
	Run: func(cmd *cobra.Command, args []string) {
		if orgId == "" {
			log.Fatalf("error: empty org not allowed")
		}

		token_content := ""
		if token_content == "" {

			listener, err := net.Listen("tcp", "localhost:")
			if err != nil {
				log.Fatalln("Error: Unable to start local http listener.")
			}

			local_port := listener.Addr().(*net.TCPAddr).Port
			url := fmt.Sprintf("%s/client/auth/org/%s?port=%d", mysocket_mtls_url, orgId, local_port)
			token_content = launch(url, listener)
		}

		jwt_token, err := jwt.Parse(token_content, nil)
		if jwt_token == nil {
			log.Fatalf("couldn't parse token: %v", err.Error())
		}

		claims := jwt_token.Claims.(jwt.MapClaims)
		if _, ok := claims["user_email"]; ok {
		} else {
			log.Fatalf("Can't find claim for user_email")
		}

		u, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		// Write to clientTokenfile
		f, err := os.Create(clientTokenfile(u.HomeDir))
		if err != nil {
			log.Fatalf("couldn't write token: %v", err.Error())
		}
		defer f.Close()
		if err := os.Chmod(clientTokenfile(u.HomeDir), 0600); err != nil {
			log.Fatalf("couldn't change permission for token file: %v", err.Error())
		}

		_, err = f.WriteString(fmt.Sprintf("%s\n", token_content))
		if err != nil {
			log.Fatalf("couldn't write token to file: %v", err.Error())
		}

		// check if installed
		switch runtime.GOOS {
		case "darwin":
			path := "/Library/LaunchDaemons/" + service_name + ".plist"
			if _, err := os.Stat(path); os.IsNotExist(err) {
				fmt.Println("Note, mysocket service not installed! ")
				fmt.Println("please run this to install the service:")
				fmt.Println("sudo " + os.Args[0] + " client service install")
				return

			}
		}
		processes, err := process.Processes()
		if err != nil {
			panic(err)
		}
		foundProcess := false
		for _, p := range processes {
			cmdline, _ := p.Cmdline()
			// See if it looks like the process we're  looking for
			res := strings.Contains(cmdline, " client dnsupdater --homedir ") //
			if res {
				//fmt.Println("MATCH for ", cmdline)
				//name, _ := p.Name()
				//fmt.Println(p, name)
				foundProcess = true
				break
			}
		}
		if foundProcess == false {
			fmt.Println("Service not running! Please start the service using:")
			fmt.Println("sudo " + os.Args[0] + " client service start")
			return
		}

		fmt.Println("Login successful")

	},
}

// clientLoginCmd represents the client login DNS command
var clientLoginStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check login status, see if token is still valid",
	Run: func(cmd *cobra.Command, args []string) {
		u, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}

		token, err := getClientToken(u.HomeDir)
		if err != nil {
			errlog.Printf("couldn't get client token  %v", err.Error())
		}

		userEmail, err := validateClientToken(token)
		if err != nil {
			fmt.Println(err)
			fmt.Println("Please login again: mysocketctl client login")
		} else {
			fmt.Println("Token Valid, logged in as " + userEmail)
		}

	},
}

// clientDnsUpdaterCmd represents the client dnsupdater command
var clientDnsUpdaterCmd = &cobra.Command{
	Use:   "dnsupdater",
	Short: "this is used by the client service. Updates local dns hosts file with private domains",
	Run: func(cmd *cobra.Command, args []string) {

		if dnsupdater_homedir == "" {
			u, err := user.Current()
			if err != nil {
				log.Fatal(err)
			}
			dnsupdater_homedir = u.HomeDir
		}
		// a default refresh rate to start. will get overwritten by the value returned in API
		// this is to prevent client from overwhelming the API, ie. we can adjust it on API side.

		refresh_rate := 300
		for {
			refresh_rate, _ = update_dns(dnsupdater_homedir)
			time.Sleep(time.Duration(refresh_rate) * time.Second)
		}

	},
}

// clientServiceCmd represents the client service command
var clientServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Install, Remove, Start and Stop the mysocketctl client service",

	Run: func(cmd *cobra.Command, args []string) {

		// Default type is SystemDaemon
		// SystemDaemon is a system daemon that runs as the root user. In other words,
		// system-wide daemons provided by the administrator. Valid for FreeBSD, Linux
		// and Windows only.
		deamonType := daemon.SystemDaemon
		if runtime.GOOS == "darwin" {
			// GlobalDaemon is a system daemon that runs as the root user and stores its
			// property list in the global LaunchDaemons directory. In other words,
			// system-wide daemons provided by the administrator. Valid for macOS only.
			deamonType = daemon.GlobalDaemon
		}

		srv, err := daemon.New(service_name, service_description, deamonType, service_dependencies...)
		if err != nil {
			errlog.Println("Error: ", err)
			os.Exit(1)
		}
		service := &Service{srv}
		status, err := service.Manage()
		if err != nil {
			errlog.Println(status, "\nError: ", err)
			os.Exit(1)
		}
		fmt.Println(status)
	},
}

func (service *Service) Manage() (string, error) {

	usage := fmt.Sprintf("Usage: %s %s %s install | remove | start | stop | status", os.Args[0], os.Args[1], os.Args[2])

	// if received any kind of command, do it

	if len(os.Args) > 3 {
		command := os.Args[3]
		switch command {
		case "install":
			u, err := user.Current()
			if err != nil {
				log.Fatal(err)
			}
			homedir := u.HomeDir
			// Also check for sudo users
			username := os.Getenv("SUDO_USER")
			if username != "" {
				if runtime.GOOS == "darwin" {
					// This is because of:
					// https://github.com/golang/go/issues/24383
					// os/user: LookupUser() doesn't find users on macOS when compiled with CGO_ENABLED=0
					// So we'll just hard code for MACOS
					homedir = "/Users/" + username
				} else {
					u, err = user.Lookup(username)
					if err != nil {
						log.Fatal(err)
					}
					homedir = u.HomeDir
				}
			}

			result, err := service.Install("client", "dnsupdater", "--homedir", homedir)
			if err != nil {
				return result, err
			}
			// Also start the service
			fmt.Println(result)
			return service.Start()

		case "remove":
			result, err := service.Stop()
			if err == nil {
				fmt.Println(result)
			}
			return service.Remove()
		case "start":
			return service.Start()
		case "stop":
			return service.Stop()
		case "status":
			return service.Status()
		default:
			return usage, nil
		}

	}
	return usage, nil

}

func validateClientToken(token string) (email string, err error) {
	userEmail := ""
	jwt_token, err := jwt.Parse(token, nil)
	if jwt_token == nil {
		return userEmail, fmt.Errorf("couldn't parse token: %v", err.Error())
	}

	claims := jwt_token.Claims.(jwt.MapClaims)
	if _, ok := claims["user_email"]; ok {
		userEmail = claims["user_email"].(string)
	} else {
		return userEmail, fmt.Errorf("Can't find claim for user_email")
	}

	now := time.Now().Unix()
	if claims.VerifyExpiresAt(now, false) == false {
		exp := claims["exp"].(float64)
		delta := time.Unix(now, 0).Sub(time.Unix(int64(exp), 0))
		return userEmail, fmt.Errorf("Token Expired. token for %s expired %v ago", userEmail, delta)
	}
	return userEmail, nil
}

func clientTokenfile(homedir string) string {
	tokenfile := ""
	if runtime.GOOS == "windows" {
		// Not sure what this should be for windows... probably wont work as is
		// service will run as admin, so not to adust this?
		//tokenfile = fmt.Sprintf("%s/.mysocketio_client_token", os.Getenv("APPDATA"))
		tokenfile = fmt.Sprintf("%s/.mysocketio_client_token", homedir)
	} else {
		tokenfile = fmt.Sprintf("%s/.mysocketio_client_token", homedir)
	}
	return tokenfile
}

func getClientToken(homedir string) (string, error) {
	if _, err := os.Stat(clientTokenfile(homedir)); os.IsNotExist(err) {
		fmt.Println(clientTokenfile(homedir))
		return "", errors.New(fmt.Sprintf("Please login first (no token found in " + clientTokenfile(homedir) + ")"))
	}
	content, err := ioutil.ReadFile(clientTokenfile(homedir))
	if err != nil {
		return "", err
	}

	tokenString := strings.TrimRight(string(content), "\n")
	return tokenString, nil
}

func update_dns(homedir string) (refreshInt int, err error) {

	stdlog = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	errlog = log.New(os.Stderr, "", log.Ldate|log.Ltime)

	//default refresh rate is 60secs
	refreshRate := 60
	//Now get the DNS domains request
	token, err := getClientToken(homedir)
	if err != nil {
		errlog.Printf("couldn't get client token  %v", err.Error())
		return refreshRate, err
	}

	// check if we have a valid token before hitting API
	_, err = validateClientToken(token)
	if err != nil {
		errlog.Printf(err.Error())
		return refreshRate, err
	}

	dnsDomains := mhttp.DnsDomains{}

	client := http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/client/resources", mysocket_api_url), nil)
	req.Header.Add("x-access-token", token)
	resp, err := client.Do(req)
	if err != nil {
		errlog.Printf("couldn't request dnsrecords  %v", err.Error())
		return refreshRate, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		errlog.Println("Error: No valid token, Please login")
		return refreshRate, err
	}

	if resp.StatusCode != 200 {
		errlog.Printf("Error: Failed to get DNS records.. HTTP code not 200 but %d", resp.StatusCode)
		return refreshRate, err
	}

	err = json.NewDecoder(resp.Body).Decode(&dnsDomains)
	if err != nil {
		errlog.Printf("couldn't parse dnsrecords response  %v", err.Error())
		return refreshRate, err
	}

	// Set refresh hint to what came back from API
	refreshRate = dnsDomains.RefreshHint

	// Add DNS entriess
	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		errlog.Printf("couldn't instantiate hosts file  %v", err.Error())
		return refreshRate, err
	}

	for _, ipAddress := range dnsDomains.DefaultIpAddresses {
		hosts.RemoveAddress(ipAddress)
	}

	for _, resource := range dnsDomains.DomainResources {
		if resource.Private_socket == true {
			for _, domain := range resource.Domains {
				stdlog.Println(domain, resource.IpAddress)
				hosts.AddHost(resource.IpAddress, domain)
			}
		}
	}

	err = hosts.Save()
	if err != nil {
		errlog.Printf("couldn't save file: %v", err.Error())
		return refreshRate, err
	}
	return refreshRate, nil

}

func mtls_tokenfile(dnsname string) string {
	tokenfile := ""
	if runtime.GOOS == "windows" {
		tokenfile = fmt.Sprintf("%s/.mysocketio_token_%s", os.Getenv("APPDATA"), dnsname)
	} else {
		tokenfile = fmt.Sprintf("%s/.mysocketio_token_%s", os.Getenv("HOME"), dnsname)
	}
	return tokenfile
}
func tcp_con_handle(con net.Conn) {
	chan_to_stdout := stream_copy(con, os.Stdout)
	chan_to_remote := stream_copy(os.Stdin, con)
	select {
	case <-chan_to_stdout:
	case <-chan_to_remote:
	}
}

// Performs copy operation between streams: os and tcp streams
func stream_copy(src io.Reader, dst io.Writer) <-chan int {
	buf := make([]byte, 1024)
	sync_channel := make(chan int)
	go func() {
		defer func() {
			if con, ok := dst.(net.Conn); ok {
				con.Close()
			}
			sync_channel <- 0 // Notify that processing is finished
		}()
		for {
			var nBytes int
			var err error
			nBytes, err = src.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("Read error: %s\n", err)
				}
				break
			}
			_, err = dst.Write(buf[0:nBytes])
			if err != nil {
				log.Fatalf("Write error: %s\n", err)
			}
		}
	}()
	return sync_channel
}

func launch(url string, listener net.Listener) string {
	c := make(chan string)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		url := r.URL
		q := url.Query()

		w.Header().Set("Content-Type", "text/html")

		if q.Get("token") != "" {
			w.Header().Set("Location", mysocket_succes_url)
			w.WriteHeader(302)
			c <- q.Get("token")
		} else {
			if q.Get("error") == "org_not_found" {
				w.Header().Set("Location", mysocket_fail_url)

			} else {
				w.Header().Set("Location", mysocket_fail_url)
			}
			w.WriteHeader(302)
			c <- ""
		}
	})

	srv := &http.Server{}
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	defer srv.Shutdown(ctx)

	go func() {
		srv.Serve(listener)
	}()

	var token string
	if openBrowser(url) {
		token = <-c
	}
	if token == "" {
		log.Fatalln("Error:  login failed")
	}
	return token
}

func openBrowser(url string) bool {
	var args []string
	switch runtime.GOOS {
	case "darwin":
		args = []string{"open"}
	case "windows":
		args = []string{"cmd", "/c", "start"}
	default:
		args = []string{"xdg-open"}
	}

	cmd := exec.Command(args[0], append(args[1:], url)...)
	return cmd.Start() == nil
}

func getCert(token string, socketDNS string, email string) *CertificateResponse {
	// generate key
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	// generate csr
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   email,
			Organization: []string{socketDNS},
		},
		EmailAddresses: []string{email},
		DNSNames:       []string{socketDNS},
	}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keyBytes)})

	// sign cert request
	jv, _ := json.Marshal(CertificateSigningRequest{Csr: string(csrPem)})
	body := bytes.NewBuffer(jv)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/mtls-ca/socket/%s/csr", mysocket_api_url, socketDNS), body)
	req.Header.Add("x-access-token", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error in request: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		log.Fatalln("Error: No valid token, Please login")
	}

	if resp.StatusCode != 200 {
		log.Fatalln("Error: Failed to get cert")
	}

	cert := &CertificateResponse{}
	err = json.NewDecoder(resp.Body).Decode(cert)
	if err != nil {
		log.Fatalln("Error: Failed to decode certificate")
	}

	cert.PrivateKey = string(privateKey)
	return cert
}

func genSshKey(token string, socketDNS string) *SshSignResponse {
	// create ssh key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Error: failed to create ssh key: %v", err)
	}

	parsed, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatalf("Error: failed to create ssh key: %v", err)
	}

	// write key
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Error: failed to write ssh key: %v", err)
	}

	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: parsed})
	err = ioutil.WriteFile(fmt.Sprintf("%s/.ssh/%s", home, socketDNS), keyPem, 0600)
	if err != nil {
		log.Fatalf("Error: failed to write ssh key: %v", err)
	}

	// create public key
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatalf("Error: failed to create public ssh key: %v", err)
	}
	data := ssh.MarshalAuthorizedKey(pub)

	//post signing request
	jv, _ := json.Marshal(SshSignRequest{SshPublicKey: strings.TrimRight(string(data), "\n")})
	body := bytes.NewBuffer(jv)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/mtls-ca/socket/%s/ssh", mysocket_api_url, socketDNS), body)
	req.Header.Add("x-access-token", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error in request: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		log.Fatalln("Error: No valid token, Please login")
	}

	if resp.StatusCode != 200 {
		responseData, _ := ioutil.ReadAll(resp.Body)
		log.Fatalf("Error: Failed to get cert: %v %v", resp.StatusCode, string(responseData))
	}

	cert := &SshSignResponse{}
	err = json.NewDecoder(resp.Body).Decode(cert)
	if err != nil {
		log.Fatalln("Error: Failed to decode certificate")
	}

	return cert
}

func init() {
	stdlog = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	errlog = log.New(os.Stderr, "", log.Ldate|log.Ltime)

	rootCmd.AddCommand(clientCmd)
	clientCmd.AddCommand(clientTlsCmd)
	clientTlsCmd.Flags().StringVarP(&hostname, "host", "", "", "The mysocket target host")
	clientTlsCmd.Flags().IntVarP(&port, "port", "p", 0, "Port number")
	clientTlsCmd.MarkFlagRequired("host")

	clientCmd.AddCommand(clientLoginCmd)
	clientLoginCmd.Flags().StringVarP(&orgId, "org", "", "", "The mysocket organization id / email")
	clientLoginCmd.Flags().IntVarP(&port, "port", "p", 0, "Port number")
	clientLoginCmd.MarkFlagRequired("org")

	clientLoginCmd.AddCommand(clientLoginStatusCmd)

	clientCmd.AddCommand(clientDnsUpdaterCmd)
	clientDnsUpdaterCmd.Flags().StringVarP(&dnsupdater_homedir, "homedir", "", "", "The home dir of the user running this service, so it can find tokenfile")

	clientCmd.AddCommand(clientServiceCmd)

	clientCmd.AddCommand(clientSshKeySignCmd)
	clientSshKeySignCmd.Flags().StringVarP(&hostname, "host", "", "", "The mysocket target host")
	clientSshKeySignCmd.MarkFlagRequired("host")

	clientCmd.AddCommand(clientSshCmd)
	clientSshCmd.Flags().StringVarP(&hostname, "host", "", "", "The ssh mysocket target host")
	clientSshCmd.Flags().StringVarP(&username, "username", "", "", "Specifies the user to log in as on the remote machine")
	clientSshCmd.MarkFlagRequired("host")
	clientSshCmd.MarkFlagRequired("username")
}

// termSize gets the current window size and returns it in a window-change friendly
// format.
func termSize(fd uintptr) []byte {
	size := make([]byte, 16)

	winsize, err := term.GetWinsize(fd)
	if err != nil {
		binary.BigEndian.PutUint32(size, uint32(80))
		binary.BigEndian.PutUint32(size[4:], uint32(24))
		return size
	}

	binary.BigEndian.PutUint32(size, uint32(winsize.Width))
	binary.BigEndian.PutUint32(size[4:], uint32(winsize.Height))

	return size
}
