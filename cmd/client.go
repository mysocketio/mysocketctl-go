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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
)

const (
	mysocket_mtls_url   = "https://mtls.edge.mysocket.io"
	mysocket_api_url    = "https://api.mysocket.io"
	mysocket_succes_url = "https://mysocket.io/succes-message/"
	mysocket_fail_url   = "https://mysocket.io/fail-message/"
)

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

// clientTlsCmd represents the client tls command
var clientTlsCmd = &cobra.Command{
	Use:   "tls",
	Short: "Connect to a mysocket TLS protected socket",
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

		var cert *CertificateResponse
		if token != "" {
			cert = getCert(token, claims["socket_dns"].(string), claims["user_email"].(string))
		} else {
			log.Fatalln("Error: Login failed")
		}

		certificate, err := tls.X509KeyPair([]byte(cert.Certificate), []byte(cert.PrivateKey))
		if err != nil {
			log.Fatalf("Error: unable to load certificate: %s", err)
		}

		if createsshkey {
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
			w.Header().Set("Location", mysocket_fail_url)
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
	err = ioutil.WriteFile(fmt.Sprintf("%s/.ssh/%s.key", home, socketDNS), keyPem, 0600)
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
	rootCmd.AddCommand(clientCmd)
	clientCmd.AddCommand(clientTlsCmd)
	clientTlsCmd.Flags().StringVarP(&hostname, "host", "", "", "The mysocket target host")
	clientTlsCmd.Flags().IntVarP(&port, "port", "p", 0, "Port number")
	clientTlsCmd.Flags().BoolVarP(&createsshkey, "createsshkey", "c", false, "Generates a signed ssh Keypair")
	clientTlsCmd.MarkFlagRequired("host")
}
