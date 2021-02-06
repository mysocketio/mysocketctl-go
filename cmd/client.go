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
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

const (
	mysocket_mtls_url   = "https://mtls.edge.mysocket.io"
	mysocket_api_url    = "https://api.mysocket.io"
	mysocket_succes_url = "https://mysocket.io/succes-message/"
	mysocket_fail_url   = "https://mysocket.io/fail-message/"
)

type CertificateReponse struct {
	PrivateKey  string `json:"client_private_key,omitempty"`
	Certificate string `json:"client_certificate,omitempty"`
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
		var cert *CertificateReponse
		if token != "" {
			cert = getCert(token, hostname)
		} else {
			log.Fatalln("Error: Login failed")
		}

		certificate, err := tls.X509KeyPair([]byte(cert.Certificate), []byte(cert.PrivateKey))
		if err != nil {
			log.Fatalf("Error: unable to load certificate: %s", err)
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

func getCert(token string, hostname string) *CertificateReponse {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/mtls-ca/socket/%s/cert", mysocket_api_url, hostname), nil)
	req.Header.Add("x-access-token", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln("Error in request: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		log.Fatalln("Error: No valid token, Please login")
	}

	if resp.StatusCode != 200 {
		log.Fatalln("Error: Failed to get cert")
	}

	cert := &CertificateReponse{}
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
	clientTlsCmd.MarkFlagRequired("host")
	clientTlsCmd.MarkFlagRequired("port")
}
