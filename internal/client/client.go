package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
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
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt"
	"github.com/moby/term"
	"github.com/mysocketio/mysocketctl-go/internal/client/password"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"golang.org/x/crypto/ssh"
)

const (
	mysocketSuccessURL = "https://mysocket.io/succes-message/"
	mysocketFailURL    = "https://mysocket.io/fail-message/"
)

func apiUrl() string {
	if os.Getenv("MYSOCKET_API") != "" {
		return os.Getenv("MYSOCKET_API")
	} else {
		return "https://api.border0.com/api/v1"
	}
}

func MTLSLogin(hostname string) (string, jwt.MapClaims, error) {
	if hostname == "" {
		return "", nil, errors.New("empty hostname not allowed")
	}

	tokenFile := MTLSTokenFile()
	var token string

	if _, err := os.Stat(tokenFile); err == nil {
		content, _ := ioutil.ReadFile(tokenFile)
		tokenString := strings.TrimRight(string(content), "\n")
		tmpJWT, _ := jwt.Parse(tokenString, nil)

		if tmpJWT != nil {
			claims := tmpJWT.Claims.(jwt.MapClaims)
			exp := int64(claims["exp"].(float64))

			if exp-10 > time.Now().Unix() {
				token = tokenString
			}
		}
	}

	_, err := FetchResource(token, hostname)
	if err != nil {
		token = ""
	}

	if token == "" {
		listener, err := net.Listen("tcp", "localhost:")
		if err != nil {
			return "", nil, fmt.Errorf("unable to start local http listener: %w", err)
		}

		localPort := listener.Addr().(*net.TCPAddr).Port
		url := fmt.Sprintf("%s/mtls-ca/socket/%s/auth?port=%d", apiUrl(), hostname, localPort)
		token = Launch(url, listener)

		f, err := os.Create(tokenFile)
		if err != nil {
			return "", nil, fmt.Errorf("failed to create token: %w", err)
		}
		if err = os.Chmod(tokenFile, 0600); err != nil {
			return "", nil, fmt.Errorf("failed to write token: %w", err)
		}
		defer f.Close()
		if _, err = f.WriteString(fmt.Sprintf("%s\n", token)); err != nil {
			return "", nil, fmt.Errorf("failed to write token: %w", err)
		}
	}

	parsedJWT, err := jwt.Parse(token, nil)
	if parsedJWT == nil {
		return "", nil, fmt.Errorf("couldn't parse token: %w", err)
	}

	claims := parsedJWT.Claims.(jwt.MapClaims)
	if _, ok := claims["user_email"]; !ok {
		return "", nil, errors.New("can't find claim for user_email")
	}

	if _, ok := claims["org_id"]; !ok {
		return "", nil, errors.New("can't find claim for org_id")
	}

	if token == "" {
		return "", nil, errors.New("login failed")
	}

	return token, claims, nil
}

func ReadOrgCert(orgID string) (cert *x509.Certificate, key *rsa.PrivateKey, crtPath string, keyPath string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		err = fmt.Errorf("error: failed to get homedir : %w", err)
		return
	}

	crtPath = filepath.Join(home, ".mysocketio", orgID+".crt")
	if _, err = os.Stat(crtPath); os.IsNotExist(err) {
		err = fmt.Errorf("error: certificate file %s not found", crtPath)
		return
	}

	keyPath = filepath.Join(home, ".mysocketio", orgID+".key")
	if _, err = os.Stat(crtPath); os.IsNotExist(err) {
		err = fmt.Errorf("error: key file %s not found", keyPath)
		return
	}

	keyPEM, err := ioutil.ReadFile(keyPath)
	if err != nil {
		err = fmt.Errorf("error: failed to read key file : %w", err)
		return
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		err = fmt.Errorf("error: failed to decode certificate file : %w", err)
		return
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		err = fmt.Errorf("error: failed to parse key file : %w", err)
		return
	}

	key, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		err = fmt.Errorf("error: failed to parse key file")
		return
	}

	certPEM, err := ioutil.ReadFile(crtPath)
	if err != nil {
		err = fmt.Errorf("error: failed to read certificate file : %w", err)
		return
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		err = fmt.Errorf("error: failed to decode certificate file : %w", err)
		return
	}

	cert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		err = fmt.Errorf("error: failed to parse certificate file : %w", err)
		return
	}

	return
}

func WriteCertToFile(cert *CertificateResponse, socketDNS string) (crtPath, keyPath string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		err = fmt.Errorf("error: failed to get homedir : %w", err)
		return
	}

	// create dir if not exists
	dotDir := filepath.Join(home, ".mysocketio")
	if _, err = os.Stat(dotDir); os.IsNotExist(err) {
		if err = os.Mkdir(dotDir, 0700); err != nil {
			err = fmt.Errorf("error: failed to create directory %s : %w", dotDir, err)
			return
		}
	}

	crtPath = filepath.Join(dotDir, socketDNS+".crt")
	keyPath = filepath.Join(dotDir, socketDNS+".key")

	if err = ioutil.WriteFile(keyPath, []byte(cert.PrivateKey), 0600); err != nil {
		err = fmt.Errorf("error: failed to write key file : %w", err)
		return
	}

	if err = ioutil.WriteFile(crtPath, []byte(cert.Certificate), 0600); err != nil {
		err = fmt.Errorf("error: failed to write certificate file : %w", err)
		return
	}

	return crtPath, keyPath, nil
}

func GetSocketPort(name string, token string) (socketPort int, err error) {

	resource, err := FetchResource(token, name)

	if err != nil {
		return socketPort, err
	}

	return resource.SocketPorts[0], nil
}

func OrgIDFromToken() (orgID string) {
	tokenfile := MTLSTokenFile()
	if _, err := os.Stat(tokenfile); os.IsNotExist(err) {
		return
	} else {
		content, _ := ioutil.ReadFile(tokenfile)
		if err == nil {
			tokenString := strings.TrimRight(string(content), "\n")
			jwtToken, _ := jwt.Parse(tokenString, nil)
			if jwtToken != nil {
				claims := jwtToken.Claims.(jwt.MapClaims)

				if _, ok := claims["org_id"]; ok {
					orgID = claims["org_id"].(string)
				}
			}
		}
	}

	return
}

func IsClientCertValid() (crtPath, keyPath string, valid bool) {
	orgID := OrgIDFromToken()

	if orgID == "" {
		return
	}

	cert, _, crtPath, keyPath, err := ReadOrgCert(orgID)
	if err != nil {
		return
	}

	if time.Now().Before(cert.NotAfter) && time.Now().After(cert.NotBefore) {
		valid = true
	}

	return
}

func FetchCertAndReturnPaths(hostname string) (crtPath, keyPath string, socketPort int, err error) {
	token, claims, err := MTLSLogin(hostname)
	if err != nil {
		return
	}

	userEmail := fmt.Sprint(claims["user_email"])
	orgID := fmt.Sprint(claims["org_id"])

	cert := GetCert(token, userEmail)
	crtPath, keyPath, err = WriteCertToFile(cert, orgID)
	if err != nil {
		return
	}

	socketPort, err = GetSocketPort(hostname, token)
	if err != nil {
		return
	}

	return
}

func GetOrgCert(hostname string) (*x509.Certificate, *rsa.PrivateKey, string, string, int, error) {
	var ok bool
	var err error
	var port int
	var claims jwt.MapClaims
	var token, certPath, keyPath string

	token, claims, err = MTLSLogin(hostname)
	if err != nil {
		return nil, nil, "", "", 0, err
	}

	if certPath, keyPath, ok = IsClientCertValid(); ok {
		port, err = GetSocketPort(hostname, token)
		if err != nil {
			return nil, nil, "", "", 0, err
		}
	} else {
		certPath, keyPath, port, err = FetchCertAndReturnPaths(hostname)
		if err != nil {
			return nil, nil, "", "", 0, err
		}
	}

	cert, key, _, _, err := ReadOrgCert(claims["org_id"].(string))
	if err != nil {
		return nil, nil, "", "", 0, err
	}

	return cert, key, certPath, keyPath, port, nil
}

func MTLSTokenFile() string {
	home := os.Getenv("HOME")
	if runtime.GOOS == "windows" {
		home = os.Getenv("APPDATA")
	}
	// return filepath.Join(home, ".mysocketio_token_"+dnsname)
	return filepath.Join(home, ".mysocketio_client_token")
}

func Launch(url string, listener net.Listener) string {
	c := make(chan string)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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

	srv := &http.Server{
		Handler: mux,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error: unable to start login process - %s", err)
		}
	}()

	var token string
	if openBrowser(url) {
		token = <-c
		srv.Shutdown(ctx)
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

func GetCert(token string, email string) *CertificateResponse {
	// generate key
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	// generate csr
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: email,
		},
		EmailAddresses: []string{email},
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(keyBytes)
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes})

	// sign cert request
	jv, _ := json.Marshal(CertificateSigningRequest{Csr: string(csrPem)})
	body := bytes.NewBuffer(jv)
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/organizations/csr", apiUrl()), body)
	req.Header.Add("x-access-token", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error in request: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		fmt.Printf("req: %+v\n", req)
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

type SSHSignRequest struct {
	SSHPublicKey string `json:"ssh_public_key"`
}

type SSHSignResponse struct {
	SSHCertSigned string `json:"signed_ssh_cert"`
}

func validSshCert(certFile string, keyFile string) *SSHSignResponse {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return nil
	}

	sshCert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil
	}

	if _, err = os.Stat(keyFile); os.IsNotExist(err) {
		return nil
	}

	sshKeyData, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil
	}

	sshKey, err := ssh.ParsePrivateKey(sshKeyData)
	if err != nil {
		return nil
	}

	pubcert, _, _, _, err := ssh.ParseAuthorizedKey(sshCert)
	if err != nil {
		return nil
	}

	cert, ok := pubcert.(*ssh.Certificate)
	if !ok {
		return nil
	}

	_, err = ssh.NewCertSigner(cert, sshKey)
	if err != nil {
		return nil
	}

	if time.Now().Unix() > int64(cert.ValidAfter) && time.Now().Unix() < int64(cert.ValidBefore) {
		return &SSHSignResponse{SSHCertSigned: string(sshCert)}
	}

	return nil
}

func GenSSHKey(token, orgID, hostname string) (*SSHSignResponse, error) {
	_, err := FetchResource(token, hostname)
	if err != nil {
		return nil, fmt.Errorf("invalid resource: %s", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to write ssh key: %v", err)
	}

	// check existing key is still valid
	sshCertPath := filepath.Join(home, ".ssh", fmt.Sprintf("%s-cert.pub", orgID))
	sshKeyPath := filepath.Join(home, ".ssh", orgID)
	sshCert := validSshCert(sshCertPath, sshKeyPath)

	if sshCert != nil {
		return sshCert, nil
	}

	if _, err := os.Stat(filepath.Join(home, ".ssh")); os.IsNotExist(err) {
		err := os.Mkdir(filepath.Join(home, ".ssh"), 0700)
		if err != nil {
			return nil, fmt.Errorf("failed to create ssh directory: %s", err)
		}
	}

	// create ssh key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create ssh key: %v", err)
	}

	parsed, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ssh key: %v", err)
	}

	// write key
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: parsed})
	err = ioutil.WriteFile(sshKeyPath, keyPem, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write ssh key: %v", err)
	}

	// create public key
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create public ssh key: %v", err)
	}
	data := ssh.MarshalAuthorizedKey(pub)

	//post signing request
	jv, _ := json.Marshal(SSHSignRequest{SSHPublicKey: strings.TrimRight(string(data), "\n")})
	body := bytes.NewBuffer(jv)
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/organizations/sign_ssh_key", apiUrl()), body)
	req.Header.Add("x-access-token", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to sign key: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		log.Fatalln("error: no valid token, Please login")
	}

	if resp.StatusCode != 200 {
		log.Fatalln("error: failed to get cert")
	}

	cert := &SSHSignResponse{}
	err = json.NewDecoder(resp.Body).Decode(cert)
	if err != nil {
		log.Fatalln("error: failed to decode certificate")
	}

	err = ioutil.WriteFile(sshCertPath, []byte(cert.SSHCertSigned), 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write ssh key: %w", err)
	}

	return cert, nil
}

func ExecCommand(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func CertToKeyStore(cert *x509.Certificate, key *rsa.PrivateKey) (ks keystore.KeyStore, pass []byte, err error) {
	// for more about keystore and jdbc to mysql connection with ssl, see:
	// https://dev.mysql.com/doc/connector-j/8.0/en/connector-j-reference-using-ssl.html
	ks = keystore.New()

	// privateKeyBlock, _ := pem.Decode([]byte(cert.PrivateKey))
	// if privateKeyBlock == nil {
	// 	err = errors.New("private key should have at least one pem block")
	// 	return
	// }
	// certificateBlock, _ := pem.Decode([]byte(cert.Certificate))
	// if certificateBlock == nil {
	// 	err = errors.New("certificate should have at least one pem block")
	// 	return
	// }

	keyData, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fmt.Println("hier dus fout")
		return
	}

	entry := keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   keyData,
		CertificateChain: []keystore.Certificate{
			{
				Type:    "X509",
				Content: cert.Raw,
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

// TermSize gets the current window size and returns it in a window-change friendly format.
func TermSize(fd uintptr) []byte {
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

func OnInterruptDo(action func()) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		defer signal.Stop(sigChan)
		<-sigChan
		action()
		os.Exit(1)
	}()
}
