package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	h "net/http"
	"os"
	"runtime"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

const (
	download_url = "https://download.edge.mysocket.io"
)

type Client struct {
	token string
}

func apiUrl() string {
	if os.Getenv("MYSOCKET_API") != "" {
		return os.Getenv("MYSOCKET_API")
	} else {
		return "https://api.mysocket.io"
	}
}

func tokenfile() string {
	tokenfile := ""
	if runtime.GOOS == "windows" {
		tokenfile = fmt.Sprintf("%s/.mysocketio_token", os.Getenv("APPDATA"))
	} else {
		tokenfile = fmt.Sprintf("%s/.mysocketio_token", os.Getenv("HOME"))
	}
	return tokenfile
}

func NewClient() (*Client, error) {
	token, err := GetToken()
	if err != nil {
		return nil, err
	}

	c := &Client{token: token}

	return c, nil
}

func (c *Client) Request(method string, url string, target interface{}, data interface{}) error {
	jv, _ := json.Marshal(data)
	body := bytes.NewBuffer(jv)

	req, _ := h.NewRequest(method, fmt.Sprintf("%s/%s", apiUrl(), url), body)
	req.Header.Add("x-access-token", c.token)
	req.Header.Set("Content-Type", "application/json")
	client := &h.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return errors.New("no valid token, Please login")
	}

	if resp.StatusCode < 200 || resp.StatusCode > 204 {
		responseData, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to create object (%d) %v", resp.StatusCode, string(responseData))
	}

	if resp.StatusCode == 204 {
		return nil
	}

	err = json.NewDecoder(resp.Body).Decode(target)
	if err != nil {
		return errors.New("failed to decode data")
	}

	return nil
}

func RefreshLogin() (string, error) {

	client, err := NewClient()
	if err != nil {
		return "", err
	}
	loginRefresh := LoginRefresh{}
	res := TokenForm{}

	err = client.Request("POST", "login/refresh", &res, loginRefresh)
	if err != nil {
		return "", err
	}

	f, err := os.Create(tokenfile())
	if err != nil {
		return "", err
	}
	if err := os.Chmod(tokenfile(), 0600); err != nil {
		return "", err
	}
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf("%s\n", res.Token))
	if err != nil {
		return "", err
	}
	return res.Token, nil
}

func Login(email, password string) error {
	c := &Client{}
	form := loginForm{Email: email, Password: password}
	buf, err := json.Marshal(form)
	if err != nil {
		return err
	}

	requestReader := bytes.NewReader(buf)

	resp, err := h.Post(apiUrl()+"/login", "application/json", requestReader)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return errors.New("Login failed")
	}

	if resp.StatusCode != 200 {
		return errors.New("failed to login")
	}

	res := TokenForm{}
	json.NewDecoder(resp.Body).Decode(&res)

	c.token = res.Token

	f, err := os.Create(tokenfile())
	if err != nil {
		return err
	}

	if err := os.Chmod(tokenfile(), 0600); err != nil {
		return err
	}

	defer f.Close()
	_, err2 := f.WriteString(fmt.Sprintf("%s\n", c.token))
	if err2 != nil {
		return err2
	}

	return nil
}

func Register(name, email, password, sshkey string) error {
	form := registerForm{Name: name, Email: email, Password: password, Sshkey: sshkey}
	buf, err := json.Marshal(form)
	if err != nil {
		return err
	}
	requestReader := bytes.NewReader(buf)
	resp, err := h.Post(apiUrl()+"/user", "application/json", requestReader)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		responseData, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to register user %d\n%v", resp.StatusCode, string(responseData))
	}
	return nil
}

func GetLatestVersion() (string, error) {
	client := &h.Client{}
	req, _ := h.NewRequest("GET", download_url+"/latest_version.txt", nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("version check failed. Failed to get latest version (%d)", resp.StatusCode)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	bodyString := string(bodyBytes)
	version := strings.TrimSpace(string(bodyString))
	version = strings.TrimSuffix(version, "\n")
	return version, nil
}

func GetLatestBinary(osname string, osarch string) (string, []byte, error) {
	var bin_url string
	var checksum_url string
	switch osname {
	case "darwin":
		if osarch == "amd64" {
			bin_url = download_url + "/darwin_amd64/mysocketctl"
			checksum_url = download_url + "/darwin_amd64/sha256-checksum.txt"
		} else if osarch == "arm64" {
			bin_url = download_url + "/darwin_arm64/mysocketctl"
			checksum_url = download_url + "/darwin_arm64/sha256-checksum.txt"
		}
	case "linux":
		if osarch == "arm64" {
			bin_url = download_url + "/linux_arm64/mysocketctl"
			checksum_url = download_url + "/linux_arm64/sha256-checksum.txt"
		} else if osarch == "arm" {
			bin_url = download_url + "/linux_arm/mysocketctl"
			checksum_url = download_url + "/linux_arm/sha256-checksum.txt"
		} else {
			bin_url = download_url + "/linux_amd64/mysocketctl"
			checksum_url = download_url + "/linux_amd64/sha256-checksum.txt"
		}
	case "windows":
		bin_url = download_url + "/windows_amd64/mysocketctl.exe"
		checksum_url = download_url + "/windows_amd64/sha256-checksum.txt"
	default:
		return "", nil, fmt.Errorf("unknown OS: %s", osname)
	}

	client := &h.Client{}
	// Download checksum
	req, _ := h.NewRequest("GET", checksum_url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", nil, fmt.Errorf("failed to get latest checksum version (%d)", resp.StatusCode)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}

	bodyString := string(bodyBytes)
	checksum := strings.TrimSpace(string(bodyString))
	checksum = strings.TrimSuffix(checksum, "\n")

	// Download binary
	req, _ = h.NewRequest("GET", bin_url, nil)
	resp, err = client.Do(req)
	if err != nil {
		return "", nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", nil, fmt.Errorf("failed to get latest version (%d)", resp.StatusCode)
	}

	bodyBytes, err2 := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err2
	}
	return checksum, bodyBytes, nil
}

func GetToken() (string, error) {
	if _, err := os.Stat(tokenfile()); os.IsNotExist(err) {
		return "", errors.New("please login first (no token found)")
	}
	content, err := ioutil.ReadFile(tokenfile())
	if err != nil {
		return "", err
	}

	tokenString := strings.TrimRight(string(content), "\n")
	return tokenString, nil
}

func GetTunnel(socketID string, tunnelID string) (*Tunnel, error) {
	tunnel := Tunnel{}
	token, err := GetToken()
	if err != nil {
		return nil, err
	}

	client := &h.Client{}
	req, _ := h.NewRequest("GET", apiUrl()+"/socket/"+socketID+"/tunnel/"+tunnelID, nil)
	req.Header.Add("x-access-token", token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get tunnel (%d)", resp.StatusCode)
	}

	err = json.NewDecoder(resp.Body).Decode(&tunnel)
	if err != nil {
		return nil, errors.New("failed to decode tunnel response")
	}
	return &tunnel, nil
}

func GetUserID() (*string, *string, error) {
	tokenStr, err := GetToken()
	if err != nil {
		return nil, nil, err
	}

	token, err := jwt.Parse(tokenStr, nil)
	if token == nil {
		return nil, nil, err
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	tokenUserId := fmt.Sprintf("%v", claims["user_id"])
	userID := strings.ReplaceAll(tokenUserId, "-", "")

	return &userID, &tokenUserId, nil
}
