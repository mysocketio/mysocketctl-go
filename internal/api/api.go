package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	mysocketctlhttp "github.com/mysocketio/mysocketctl-go/internal/http"
)

const APIUrl = "https://api.mysocket.io"

var ErrUnauthorized = errors.New("unauthorized")

type API struct {
	AccessToken string
	Version     string
}

type ErrorMessage struct {
	ErrorMessage string `json:"error_message,omitempty"`
}

func NewAPI(accessToken string) *API {
	return &API{AccessToken: accessToken}
}

func APIURL() string {
	if os.Getenv("MYSOCKET_API") != "" {
		return os.Getenv("MYSOCKET_API")
	} else {
		return APIUrl
	}
}

func (a *API) Request(method string, url string, target interface{}, data interface{}) error {
	if a.AccessToken == "" {
		token, err := mysocketctlhttp.GetToken()
		if err != nil {
			return err
		}

		a.AccessToken = token
	}

	jv, _ := json.Marshal(data)
	body := bytes.NewBuffer(jv)

	req, _ := http.NewRequest(method, fmt.Sprintf("%s/%s", APIURL(), url), body)

	sanitizedAccessToken := strings.Trim(a.AccessToken, "\n")
	sanitizedAccessToken = strings.Trim(sanitizedAccessToken, " ")

	req.Header.Add("x-access-token", sanitizedAccessToken)
	req.Header.Add("x-client-requested-with", "mysocketctl")
	if a.Version != "" {
		req.Header.Add("x-client-version", a.Version)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return ErrUnauthorized
	}

	if resp.StatusCode == 429 {
		responseData, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("rate limit error: %v", string(responseData))
	}

	if resp.StatusCode < 200 || resp.StatusCode > 204 {
		var errorMessage ErrorMessage
		json.NewDecoder(resp.Body).Decode(&errorMessage)

		return fmt.Errorf("failed to create object (%d) %v", resp.StatusCode, errorMessage.ErrorMessage)
	}

	if resp.StatusCode == 204 {
		return nil
	}

	err = json.NewDecoder(resp.Body).Decode(target)
	if err != nil {
		return fmt.Errorf("failede to decode request body: %w", err)
	}

	return nil
}

func (a *API) GetOrganizationInfo(ctx context.Context) (*models.Organization, error) {
	org := models.Organization{}

	err := a.Request("GET", "organization", &org, nil)
	if err != nil {
		return nil, err
	}

	return &org, nil
}

func (a *API) GetSockets(ctx context.Context) ([]models.Socket, error) {
	sockets := []models.Socket{}

	err := a.Request("GET", "socket", &sockets, nil)
	if err != nil {
		return nil, err
	}

	return sockets, nil
}

func (a *API) GetSocket(ctx context.Context, socketID string) (*models.Socket, error) {
	socket := models.Socket{}

	err := a.Request("GET", fmt.Sprintf("socket/%v", socketID), &socket, nil)
	if err != nil {
		return nil, err
	}

	return &socket, nil
}

func (a *API) GetTunnel(ctx context.Context, socketID string, tunnelID string) (*models.Tunnel, error) {
	tunnel := models.Tunnel{}

	err := a.Request("GET", fmt.Sprintf("/socket/%v/tunnel/%v", socketID, tunnelID), &tunnel, nil)
	if err != nil {
		return nil, err
	}

	return &tunnel, nil
}

func (a *API) CreateSocket(ctx context.Context, socket *models.Socket) (*models.Socket, error) {
	s := models.Socket{}

	err := a.Request("POST", "socket", &s, socket)
	if err != nil {
		return nil, err
	}

	return &s, nil
}

func (a *API) CreateTunnel(ctx context.Context, socketID string) (*models.Tunnel, error) {
	t := models.Tunnel{}

	url := fmt.Sprintf("socket/%v/tunnel", socketID)
	err := a.Request("POST", url, &t, nil)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

func (a *API) DeleteSocket(ctx context.Context, socketID string) error {
	err := a.Request("DELETE", "socket/"+socketID, nil, nil)
	if err != nil {
		return err
	}

	return nil
}

func (a *API) UpdateSocket(ctx context.Context, socketID string, socket models.Socket) error {
	var result models.Socket

	err := a.Request("PUT", "socket/"+socketID, &result, &socket)
	if err != nil {
		return err
	}

	return nil
}
