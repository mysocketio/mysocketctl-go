package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/fatih/color"
	"github.com/mysocketio/mysocketctl-go/internal/enum"
	internalhttp "github.com/mysocketio/mysocketctl-go/internal/http"
)

func Login(orgID string) (token string, claims jwt.MapClaims, err error) {
	if orgID == "" {
		err = errors.New("empty org not allowed")
		return
	}

	if token == "" {
		var listener net.Listener
		listener, err = net.Listen("tcp", "localhost:")
		if err != nil {
			err = errors.New("unable to start local http listener.")
			return
		}
		localPort := listener.Addr().(*net.TCPAddr).Port
		url := fmt.Sprintf("%s/client/auth/org/%s?port=%d", apiUrl(), orgID, localPort)
		token = Launch(url, listener)
	}

	parsedJWT, err := jwt.Parse(token, nil)
	if parsedJWT == nil {
		err = fmt.Errorf("couldn't parse token: %w", err)
		return
	}

	claims = parsedJWT.Claims.(jwt.MapClaims)
	if _, ok := claims["user_email"]; !ok {
		err = errors.New("can't find claim for user_email")
		return
	}

	currentUser, err := user.Current()
	if err != nil {
		err = fmt.Errorf("couldn't get currently logged in operating system user: %w", err)
		return
	}

	// Write to client token file
	tokenFile := ClientTokenFile(currentUser.HomeDir)
	f, err := os.Create(tokenFile)
	if err != nil {
		err = fmt.Errorf("couldn't write token: %w", err)
		return
	}
	defer f.Close()
	if err = os.Chmod(tokenFile, 0600); err != nil {
		err = fmt.Errorf("couldn't change permission for token file: %w", err)
		return
	}

	if _, err = f.WriteString(fmt.Sprintf("%s\n", token)); err != nil {
		err = fmt.Errorf("couldn't write token to file: %w", err)
		return
	}

	return token, claims, nil
}

func IsExistingClientTokenValid(homeDir string) (valid bool, token, email string, err error) {
	if homeDir == "" {
		var currentUser *user.User
		currentUser, err = user.Current()
		if err != nil {
			err = fmt.Errorf("couldn't get currently logged in operating system user: %w", err)
			return
		}
		homeDir = currentUser.HomeDir
	}
	token, err = GetClientToken(homeDir)
	if err != nil {
		err = fmt.Errorf("couldn't get client token: %w", err)
		return
	}
	email, err = ValidateClientToken(token)
	return (err == nil), token, email, err
}

func GetClientToken(homeDir string) (string, error) {
	tokenFile := ClientTokenFile(homeDir)
	if _, err := os.Stat(tokenFile); os.IsNotExist(err) {
		fmt.Println(tokenFile)
		return "", fmt.Errorf("please login first (no token found in " + tokenFile + ")")
	}
	content, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		return "", err
	}

	tokenString := strings.TrimRight(string(content), "\n")
	return tokenString, nil
}

func ClientTokenFile(homedir string) string {
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

func ValidateClientToken(token string) (email string, err error) {
	userEmail := ""
	parsedJWT, err := jwt.Parse(token, nil)
	if parsedJWT == nil {
		return userEmail, fmt.Errorf("couldn't parse token: %v", err.Error())
	}

	claims := parsedJWT.Claims.(jwt.MapClaims)
	if _, ok := claims["user_email"]; ok {
		userEmail = claims["user_email"].(string)
	} else {
		return userEmail, fmt.Errorf("can't find claim for user_email")
	}

	now := time.Now().Unix()
	if !claims.VerifyExpiresAt(now, false) {
		exp := claims["exp"].(float64)
		delta := time.Unix(now, 0).Sub(time.Unix(int64(exp), 0))
		return userEmail, fmt.Errorf("token Expired. token for %s expired %v ago", userEmail, delta)
	}
	return userEmail, nil
}

func FetchResources(token string, filteredTypes ...string) (resources internalhttp.ClientResources, err error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/client/resources", apiUrl()), nil)
	req.Header.Add("x-access-token", token)
	client := http.Client{
		Timeout: 15 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		err = fmt.Errorf("couldn't request dnsrecords: %w", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		err = errors.New("no valid token, please login")
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("failed to get DNS records.. HTTP code not 200 but %d", resp.StatusCode)
		return
	}

	if err = json.NewDecoder(resp.Body).Decode(&resources); err != nil {
		err = fmt.Errorf("couldn't parse dnsrecords response: %w", err)
		return
	}
	if len(filteredTypes) > 0 {
		allowedTypes := make(map[string]struct{})
		for _, typ := range filteredTypes {
			allowedTypes[strings.ToLower(typ)] = struct{}{}
		}
		tmp := resources.Resources[:0] // use the same block of memory to reduce allocation cost
		for _, res := range resources.Resources {
			if _, exists := allowedTypes[strings.ToLower(res.SocketType)]; exists {
				tmp = append(tmp, res)
			}
		}
		resources.Resources = tmp
	}

	return resources, nil
}

func PickHostAndEnterDBName(inputHost, inputDBName string) (pickedHost, enteredDBName string, err error) {
	pickedHost, err = PickHost(inputHost, enum.DatabaseSocket)
	if err != nil {
		return
	}

	enteredDBName = inputDBName
	if enteredDBName == "" {
		if err = survey.AskOne(&survey.Input{
			Message: "what is the name of the database schema:",
		}, &enteredDBName); err != nil {
			err = fmt.Errorf("couldn't capture database input: %w", err)
			return
		}
	}

	return pickedHost, enteredDBName, nil
}

func ReadTokenOrAskToLogIn() (token string, err error) {
	var valid bool
	valid, token, _, err = IsExistingClientTokenValid("")
	if !valid {
		fmt.Println(err)
		fmt.Println()

		var orgID string
		if err = survey.AskOne(&survey.Input{
			Message: "let's try to log in again, what is your organization id/email:",
		}, &orgID, survey.WithValidator(survey.Required)); err != nil {
			err = fmt.Errorf("couldn't collect organization id/email from input: %w", err)
			return
		}

		token, _, err = Login(orgID)
		if err != nil {
			err = fmt.Errorf("failed logging into org %s: %w", orgID, err)
			return
		}
	}
	return token, nil
}

func PickHost(inputHost string, socketTypes ...string) (pickedHost string, err error) {
	pickedHost = inputHost
	if pickedHost == "" {
		var token string
		token, err = ReadTokenOrAskToLogIn()
		if err != nil {
			return
		}

		var resources internalhttp.ClientResources
		resources, err = FetchResources(token, socketTypes...)
		if err != nil {
			err = fmt.Errorf("failed fetching client resources: %w", err)
			return
		}

		blue := color.New(color.FgBlue)
		answers := make(map[string]string)

		var hosts []string
		for _, res := range resources.Resources {
			hostToShow := res.DomainsToString() + " " + blue.Sprintf("[%s]", res.SocketName)
			hostToReturn := res.FirstDomain("")
			answers[hostToShow] = hostToReturn
			hosts = append(hosts, hostToShow)
		}

		if err = survey.AskOne(&survey.Select{
			Message: "choose a host:",
			Options: hosts,
		}, &pickedHost); err != nil {
			err = fmt.Errorf("couldn't capture host input: %w", err)
			return
		}
		pickedHost = answers[pickedHost]
	}
	return pickedHost, nil
}

func PickResourceTypes(inputFilter string) (pickedTypes []string, err error) {
	if inputFilter == "prompt" {
		allTypes := []string{enum.HTTPSocket, enum.TLSSocket, enum.SSHSocket, enum.DatabaseSocket}
		if err = survey.AskOne(&survey.MultiSelect{
			Message: "what types of resources would you like to see:",
			Options: allTypes,
			Default: allTypes,
		}, &pickedTypes); err != nil {
			err = fmt.Errorf("unable to capture input: %w", err)
			return
		}
	} else {
		pickedTypes = strings.Split(inputFilter, ",")
	}
	if len(pickedTypes) == 0 {
		err = errors.New("no resource types selected")
		return
	}
	for _, typ := range pickedTypes {
		if typ == enum.HTTPSocket {
			pickedTypes = append(pickedTypes, enum.HTTPSSocket)
		}
	}
	return pickedTypes, nil
}
