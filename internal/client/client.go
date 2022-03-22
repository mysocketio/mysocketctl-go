package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mysocketio/mysocketctl-go/internal/client/password"
	"github.com/pavel-v-chernykh/keystore-go/v4"
)

const (
	mysocketSuccessURL = "https://mysocket.io/succes-message/"
	mysocketFailURL    = "https://mysocket.io/fail-message/"
)

func apiUrl() string {
       if os.Getenv("MYSOCKET_API") != "" {
               return os.Getenv("MYSOCKET_API")
       } else {
               return "https://api.mysocket.io"
       }
}

func mtlsUrl() string {
       if os.Getenv("MYSOCKET_MTLS") != "" {
               return os.Getenv("MYSOCKET_MTLS")
       } else {
               return "https://mtls.edge.mysocket.io"
       }
}

func MTLSLogin(hostname string) (token string, claims jwt.MapClaims, err error) {
	if hostname == "" {
		err = errors.New("empty hostname not allowed")
		return
	}

	// Check if we already have a valid token
	var tokenContent string

	tokenFile := MTLSTokenFile(hostname)
	if _, err := os.Stat(tokenFile); err == nil {
		// token file exists, read from file
		content, _ := ioutil.ReadFile(tokenFile)
		tokenString := strings.TrimRight(string(content), "\n")
		tmpJWT, _ := jwt.Parse(tokenString, nil)
		if tmpJWT != nil {
			claims := tmpJWT.Claims.(jwt.MapClaims)
			exp := int64(claims["exp"].(float64))
			//  subtract 10secs from token, for expected work time
			//  If token time is larger then current time we're good
			if exp-10 > time.Now().Unix() {
				tokenContent = tokenString
			}
		}
	}

	if tokenContent == "" {
		var listener net.Listener
		listener, err = net.Listen("tcp", "localhost:")
		if err != nil {
			err = fmt.Errorf("unable to start local http listener: %w", err)
			return
		}

		localPort := listener.Addr().(*net.TCPAddr).Port
		url := fmt.Sprintf("%s/mtls-ca/socket/%s/auth?port=%d", mtlsUrl(), hostname, localPort)
		tokenContent = Launch(url, listener)
	}

	// Also write token, for future use
	f, err := os.Create(tokenFile)
	if err != nil {
		err = fmt.Errorf("failed to create token: %w", err)
		return
	}
	if err = os.Chmod(tokenFile, 0600); err != nil {
		err = fmt.Errorf("failed to write token: %w", err)
		return
	}
	defer f.Close()
	if _, err = f.WriteString(fmt.Sprintf("%s\n", tokenContent)); err != nil {
		err = fmt.Errorf("failed to write token: %w", err)
		return
	}

	parsedJWT, err := jwt.Parse(tokenContent, nil)
	if parsedJWT == nil {
		err = fmt.Errorf("couldn't parse token: %w", err)
		return
	}
	claims = parsedJWT.Claims.(jwt.MapClaims)
	if _, ok := claims["user_email"]; !ok {
		err = errors.New("can't find claim for user_email")
		return
	}
	if _, ok := claims["socket_dns"]; !ok {
		err = errors.New("can't find claim for socket_dns")
		return
	}
	if tokenContent == "" {
		err = errors.New("login failed")
		return
	}
	return tokenContent, claims, nil
}

func WriteCertToFile(cert *CertificateResponse, socketDNS string) (crtPath, keyPath string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		err = fmt.Errorf("Error: failed to get homedir : %w", err)
		return
	}

	// create dir if not exists
	dotDir := filepath.Join(home, ".mysocketio")
	if _, err = os.Stat(dotDir); os.IsNotExist(err) {
		if err = os.Mkdir(dotDir, 0700); err != nil {
			err = fmt.Errorf("Error: failed to create directory %s : %w", dotDir, err)
			return
		}
	}

	crtPath = filepath.Join(dotDir, socketDNS+".crt")
	keyPath = filepath.Join(dotDir, socketDNS+".key")

	if err = ioutil.WriteFile(keyPath, []byte(cert.PrivateKey), 0600); err != nil {
		err = fmt.Errorf("Error: failed to write key file : %w", err)
		return
	}

	if err = ioutil.WriteFile(crtPath, []byte(cert.Certificate), 0600); err != nil {
		err = fmt.Errorf("Error: failed to write certificate file : %w", err)
		return
	}

	return crtPath, keyPath, nil
}

func GetSocketPortFrom(claims jwt.MapClaims, port int) (socketPort int, err error) {
	// If user didnt set port using --port, then get it from jwt claims
	if port == 0 {
		if _, ok := claims["socket_port"]; !ok {
			return 0, errors.New("Can't find claim for socket_port")
		}
		if socketPort = int(claims["socket_port"].(float64)); socketPort == 0 {
			return 0, errors.New("Error: Unable to get tls port from token")
		}
	}
	return socketPort, nil
}

func FetchCertAndReturnPaths(hostname string, port int) (crtPath, keyPath string, socketPort int, err error) {
	token, claims, err := MTLSLogin(hostname)
	if err != nil {
		return
	}

	socketDNS := fmt.Sprint(claims["socket_dns"])
	userEmail := fmt.Sprint(claims["user_email"])

	cert := GetCert(token, socketDNS, userEmail)
	crtPath, keyPath, err = WriteCertToFile(cert, socketDNS)
	if err != nil {
		return
	}

	socketPort, err = GetSocketPortFrom(claims, port)
	if err != nil {
		return
	}

	return
}

func MTLSTokenFile(dnsname string) string {
	home := os.Getenv("HOME")
	if runtime.GOOS == "windows" {
		home = os.Getenv("APPDATA")
	}
	return filepath.Join(home, ".mysocketio_token_"+dnsname)
}

func Launch(url string, listener net.Listener) string {
	c := make(chan string)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		url := r.URL
		q := url.Query()

		w.Header().Set("Content-Type", "text/html")

		if q.Get("token") != "" {
			w.Header().Set("Location", mysocketSuccessURL)
			w.WriteHeader(302)
			c <- q.Get("token")
		} else {
			if q.Get("error") == "org_not_found" {
				w.Header().Set("Location", mysocketFailURL)

			} else {
				w.Header().Set("Location", mysocketFailURL)
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
		log.Fatalln("Error: login failed")
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

type CertificateSigningRequest struct {
	Csr string `json:"csr"`
}

type CertificateResponse struct {
	PrivateKey  string `json:"client_private_key,omitempty"`
	Certificate string `json:"client_certificate,omitempty"`
}

func GetCert(token string, socketDNS string, email string) *CertificateResponse {
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
	privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(keyBytes)
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes})

	// sign cert request
	jv, _ := json.Marshal(CertificateSigningRequest{Csr: string(csrPem)})
	body := bytes.NewBuffer(jv)
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/mtls-ca/socket/%s/csr", apiUrl(), socketDNS), body)
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

func ExecCommand(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func CertToKeyStore(cert *CertificateResponse) (ks keystore.KeyStore, pass []byte, err error) {
	// for more about keystore and jdbc to mysql connection with ssl, see:
	// https://dev.mysql.com/doc/connector-j/8.0/en/connector-j-reference-using-ssl.html
	ks = keystore.New()

	privateKeyBlock, _ := pem.Decode([]byte(cert.PrivateKey))
	if privateKeyBlock == nil {
		err = errors.New("private key should have at least one pem block")
		return
	}
	certificateBlock, _ := pem.Decode([]byte(cert.Certificate))
	if certificateBlock == nil {
		err = errors.New("certificate should have at least one pem block")
		return
	}
	entry := keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   privateKeyBlock.Bytes,
		CertificateChain: []keystore.Certificate{
			{
				Type:    "X509",
				Content: certificateBlock.Bytes,
			},
		},
	}

	pass = password.KeyStore()
	if err = ks.SetPrivateKeyEntry("mysocket", entry, pass); err != nil {
		err = fmt.Errorf("error setting encrypted private key to keystore: %w", err)
		return
	}

	return ks, pass, nil
}

func WriteKeyStore(ks keystore.KeyStore, filename string, password []byte) {
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	err = ks.Store(f, password)
	if err != nil {
		log.Fatal(err) // nolint: gocritic
	}
}

func Zeroing(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
