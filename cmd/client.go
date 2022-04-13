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
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/txn2/txeh"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/shirou/gopsutil/process"

	"github.com/mysocketio/mysocketctl-go/cmd/client/db"
	"github.com/mysocketio/mysocketctl-go/cmd/client/hosts"
	"github.com/mysocketio/mysocketctl-go/cmd/client/ssh"
	"github.com/mysocketio/mysocketctl-go/internal/client"
	"github.com/spf13/cobra"
	"github.com/takama/daemon"
)

const (
	// for Service
	service_name        = "mysocket_service"
	service_description = "MySocket.io Service"
)

var mysocket_api_url string

type Service struct {
	daemon.Daemon
}

var stdlog, errlog *log.Logger

//   dependencies that are NOT required by the service, but might be used
var service_dependencies = []string{}

// clientCmd represents the client command
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Client commands",
}

var clientCertCmd = &cobra.Command{
	Use:   "cert",
	Short: "Client certificates",
}

var clientCertFetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch Client certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		crtPath, keyPath, _, err := client.FetchCertAndReturnPaths(hostname, port)
		if err != nil {
			return err
		}

		fmt.Println("Client certificate file:", crtPath, "and", keyPath)
		return nil
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

		tokenfile := client.MTLSTokenFile(hostname)
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
			url := fmt.Sprintf("%s/mtls-ca/socket/%s/auth?port=%d", mysocket_api_url, hostname, local_port)
			token_content = client.Launch(url, listener)
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

		var cert *client.CertificateResponse
		if token_content != "" {
			cert = client.GetCert(token_content, claims["socket_dns"].(string), claims["user_email"].(string))
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

		if listener > 0 {
			l, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", listener))
			if err != nil {
				log.Fatalln("Error: Unable to start local TLS listener.")
			}

			var wg sync.WaitGroup
			wg.Add(1)

			go func() {
				defer wg.Done()
				log.Print("Waiting for connection...")
				lcon, err := l.Accept()
				if err != nil {
					log.Fatalf("Listener: Accept Error: %s\n", err)
				}
				log.Print("Connection established")
				defer lcon.Close()
				tcp_con_handle(conn, lcon, lcon)
			}()

			wg.Wait()
		} else {
			tcp_con_handle(conn, os.Stdin, os.Stdout)
		}

	},
}

// clientLoginCmd represents the client login DNS command
var clientLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login and get API token so service can authenticate",
	Run: func(cmd *cobra.Command, args []string) {
		client.Login(orgID)

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
		if !foundProcess {
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
		valid, _, email, err := client.IsExistingClientTokenValid("")
		if !valid {
			fmt.Println(err)
			fmt.Println("Please login again: mysocketctl client login")
		} else {
			fmt.Println("Token Valid, logged in as " + email)
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
			refresh_rate, _ = updateDNS(dnsupdater_homedir)
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
		case "restart":
			resultFromStop, err := service.Stop()
			if err != nil {
				return resultFromStop, err
			}
			resultFromStart, err := service.Start()
			result := resultFromStop + "\n" + resultFromStart
			return result, err
		case "status":
			return service.Status()
		default:
			return usage, nil
		}

	}
	return usage, nil

}

func updateDNS(homedir string) (refreshInt int, err error) {
	stdlog = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	errlog = log.New(os.Stderr, "", log.Ldate|log.Ltime)

	// default refresh rate is 60secs
	refreshRate := 60
	// Now get the DNS domains request
	// check if we have a valid token before hitting API
	valid, token, _, err := client.IsExistingClientTokenValid(homedir)
	if !valid {
		errlog.Printf(err.Error())
		return refreshRate, err
	}

	dnsDomains, err := client.FetchResources(token)
	if err != nil {
		errlog.Println("Error:", err)
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

	for _, ipAddress := range dnsDomains.DefaultIPAddresses {
		hosts.RemoveAddress(ipAddress)
	}

	for _, resource := range dnsDomains.Resources {
		if resource.PrivateSocket {
			for _, domain := range resource.Domains {
				stdlog.Println(domain, resource.IPAddress)
				hosts.AddHost(resource.IPAddress, domain)
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

func tcp_con_handle(con net.Conn, in io.Reader, out io.Writer) {
	chan_to_stdout := stream_copy(con, out)
	chan_to_remote := stream_copy(in, con)

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

func init() {
	stdlog = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	errlog = log.New(os.Stderr, "", log.Ldate|log.Ltime)

	if os.Getenv("MYSOCKET_API") != "" {
		mysocket_api_url = os.Getenv("MYSOCKET_API")
	} else {
		mysocket_api_url = "https://api.mysocket.io"
	}

	rootCmd.AddCommand(clientCmd)
	clientCmd.AddCommand(clientTlsCmd)
	clientTlsCmd.Flags().StringVarP(&hostname, "host", "", "", "The mysocket target host")
	clientTlsCmd.Flags().IntVarP(&port, "port", "p", 0, "Port number")
	clientTlsCmd.Flags().IntVarP(&listener, "listener", "l", 0, "Listener port number")
	clientTlsCmd.MarkFlagRequired("host")

	clientCmd.AddCommand(clientCertCmd)
	clientCertCmd.AddCommand(clientCertFetchCmd)
	clientCertFetchCmd.Flags().StringVarP(&hostname, "host", "", "", "The mysocket target host")
	clientCertFetchCmd.MarkFlagRequired("host")

	clientCmd.AddCommand(clientLoginCmd)
	clientLoginCmd.Flags().StringVarP(&orgID, "org", "", "", "The mysocket organization id / email")
	clientLoginCmd.Flags().IntVarP(&port, "port", "p", 0, "Port number")
	clientLoginCmd.MarkFlagRequired("org")

	clientLoginCmd.AddCommand(clientLoginStatusCmd)

	clientCmd.AddCommand(clientDnsUpdaterCmd)
	clientDnsUpdaterCmd.Flags().StringVarP(&dnsupdater_homedir, "homedir", "", "", "The home dir of the user running this service, so it can find tokenfile")

	clientCmd.AddCommand(clientServiceCmd)

	db.AddCommandsTo(clientCmd)
	hosts.AddCommandsTo(clientCmd)
	ssh.AddCommandsTo(clientCmd)
}
