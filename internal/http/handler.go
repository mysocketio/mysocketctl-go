package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	h "net/http"
	"os"
	"runtime"
	"strings"

	jwt "github.com/golang-jwt/jwt"
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
)

const (
	download_url = "https://download.border0.com"
)

var ErrUnauthorized = errors.New("unaouthorized")

type ErrorMessage struct {
	ErrorMessage string `json:"error_message,omitempty"`
}

type Client struct {
	token   string
	version string
}

func APIURL() string {
	return apiUrl()
}
func apiUrl() string {
	if os.Getenv("MYSOCKET_API") != "" {
		return os.Getenv("MYSOCKET_API")
	} else {
		return "https://api.border0.com/api/v1"
	}
}

func WebUrl() string {
	if os.Getenv("MYSOCKET_WEB_URL") != "" {
		return os.Getenv("MYSOCKET_WEB_URL")
	} else {
		return "https://portal.border0.com"
	}
}

func TokenFilePath() string {
	return tokenfile()
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

func NewClientWithAccessToken(token string) (*Client, error) {
	var accessToken string

	if token != "" {
		accessToken = token
	} else {
		token, err := GetToken()
		if err != nil {
			return nil, err
		}
		accessToken = token
	}

	c := &Client{token: accessToken}

	return c, nil
}

func (c *Client) WithVersion(version string) *Client {
	if version == "" {
		return c
	}
	c2 := new(Client)
	*c2 = *c
	c2.version = version
	return c2
}

func (c *Client) WithAccessToken(token string) *Client {
	if token == "" {
		return c
	}
	c2 := new(Client)
	*c2 = *c
	c2.token = token
	return c2
}

func (c *Client) Request(method string, url string, target interface{}, data interface{}) error {
	jv, _ := json.Marshal(data)
	body := bytes.NewBuffer(jv)

	req, _ := h.NewRequest(method, fmt.Sprintf("%s/%s", apiUrl(), url), body)
	req.Header.Add("x-access-token", c.token)
	req.Header.Add("x-client-requested-with", "mysocketctl")
	if c.version != "" {
		req.Header.Add("x-client-version", c.version)
	}
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

	if target != nil {
		err = json.NewDecoder(resp.Body).Decode(target)
		if err != nil {
			return errors.New("failed to decode data")
		}
	}

	return nil
}

func RefreshLogin() (string, error) {

	client, err := NewClient()
	if err != nil {
		return "", err
	}
	loginRefresh := models.LoginRefresh{}
	res := models.TokenForm{}

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

func MFAChallenge(code string) error {
	c, err := NewClient()
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	form := models.MfaForm{Code: code}
	res := models.TokenForm{}

	err = c.Request("POST", "users/mfa_challenge", &res, &form)
	if err != nil {
		return err
	}

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

func CreateDeviceAuthorization() (string, error) {
	resp, err := h.Post(apiUrl()+"/device_authorizations", "application/json", nil)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return "", ErrUnauthorized
	}

	if resp.StatusCode == 429 {
		responseData, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("unauthorized %v", string(responseData))
	}

	if resp.StatusCode != 200 {
		var errorMessage ErrorMessage
		json.NewDecoder(resp.Body).Decode(&errorMessage)

		return "", fmt.Errorf(errorMessage.ErrorMessage)
	}

	type sessionToken struct {
		Token string `json:"token,omitempty"`
	}

	var ssToken sessionToken
	json.NewDecoder(resp.Body).Decode(&ssToken)

	if ssToken.Token != "" {
		return ssToken.Token, nil
	}

	return "", errors.New("couldn't fetch the temporary token")
}

func Login(email, password string) (bool, error) {
	c := &Client{}
	form := models.LoginForm{Email: email, Password: password}
	buf, err := json.Marshal(form)
	if err != nil {
		return false, err
	}

	requestReader := bytes.NewReader(buf)

	resp, err := h.Post(apiUrl()+"/login", "application/json", requestReader)
	if err != nil {
		return false, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return false, errors.New("Login failed")
	}

	if resp.StatusCode != 200 {
		return false, errors.New("failed to login")
	}

	res := models.TokenForm{}
	json.NewDecoder(resp.Body).Decode(&res)

	c.token = res.Token

	if err := SaveTokenInDisk(c.token); err != nil {
		return false, err
	}

	return res.MFA, nil
}

func SaveTokenInDisk(accessToken string) error {
	f, err := os.Create(tokenfile())
	if err != nil {
		return err
	}

	if err := os.Chmod(tokenfile(), 0600); err != nil {
		return err
	}

	defer f.Close()
	_, err2 := f.WriteString(fmt.Sprintf("%s\n", accessToken))
	if err2 != nil {
		return err2
	}

	return nil
}

func Register(name, email, password, sshkey string) error {
	form := models.RegisterForm{Name: name, Email: email, Password: password, Sshkey: sshkey}
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
			bin_url = download_url + "/darwin_amd64/border0"
			checksum_url = download_url + "/darwin_amd64/sha256-checksum.txt"
		} else if osarch == "arm64" {
			bin_url = download_url + "/darwin_arm64/border0"
			checksum_url = download_url + "/darwin_arm64/sha256-checksum.txt"
		}
	case "linux":
		if osarch == "arm64" {
			bin_url = download_url + "/linux_arm64/border0"
			checksum_url = download_url + "/linux_arm64/sha256-checksum.txt"
		} else if osarch == "arm" {
			bin_url = download_url + "/linux_arm/border0"
			checksum_url = download_url + "/linux_arm/sha256-checksum.txt"
		} else {
			bin_url = download_url + "/linux_amd64/border0"
			checksum_url = download_url + "/linux_amd64/sha256-checksum.txt"
		}
	case "windows":
		bin_url = download_url + "/windows_amd64/border0.exe"
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

func GetTunnel(socketID string, tunnelID string) (*models.Tunnel, error) {
	tunnel := models.Tunnel{}
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

func GetDeviceAuthorization(sessionToken string) (*models.SessionTokenForm, error) {
	client := &h.Client{}
	req, _ := h.NewRequest("GET", apiUrl()+"/device_authorizations", nil)
	req.Header.Add("x-access-token", sessionToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, ErrUnauthorized
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get device_authorization (%d)", resp.StatusCode)
	}

	var form models.SessionTokenForm
	err = json.NewDecoder(resp.Body).Decode(&form)
	if err != nil {
		return nil, errors.New("failed to decode device auth response")
	}
	return &form, nil
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

func GetUserIDFromAccessToken(accessToken string) (*string, *string, error) {
	var rawToken string
	if accessToken != "" {
		rawToken = accessToken
	} else {
		tokenStr, err := GetToken()
		if err != nil {
			return nil, nil, err
		}
		rawToken = tokenStr
	}

	token, err := jwt.Parse(rawToken, nil)
	if token == nil {
		return nil, nil, err
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	tokenUserId := fmt.Sprintf("%v", claims["user_id"])
	userID := strings.ReplaceAll(tokenUserId, "-", "")

	return &userID, &tokenUserId, nil
}
