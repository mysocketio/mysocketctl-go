package discover

import (
	"context"
	"fmt"
	"time"

	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/connector/config"
)

type StaticSocketFinder struct{}

func (s *StaticSocketFinder) SkipRun(ctx context.Context, cfg config.Config, state DiscoverState) bool {
	return state.RunsCount > 1 || state.RunsCount == 1
}

func (s *StaticSocketFinder) Find(ctx context.Context, cfg config.Config, state DiscoverState) []models.Socket {
	sockets := []models.Socket{}

	for _, socketMap := range cfg.Sockets {
		socket := models.Socket{}

		socket.CloudAuthEnabled = false
		for k, v := range socketMap {
			if len(v.AllowedEmailAddresses) > 0 || len(v.AllowedEmailDomains) > 0 {
				socket.CloudAuthEnabled = true
			}

			socket.Name = k
			socket.AllowedEmailAddresses = v.AllowedEmailAddresses
			socket.AllowedEmailDomains = v.AllowedEmailDomains
			socket.SocketType = v.Type
			socket.UpstreamUsername = v.UpstreamUser
			socket.UpstreamPassword = v.UpstreamPassword
			socket.TargetHostname = v.Host
			socket.TargetPort = v.Port
			socket.PrivateSocket = v.PrivateSocket

			if v.UpstreamType == "" {
				v.UpstreamType = "http"
			}

			if socket.Description == "" {
				socket.Description = fmt.Sprintf("created by %s", cfg.Connector.Name)
			}

			if socket.PrivateSocket {
				socket.Dnsname = socket.Name
			}

			socket.UpstreamType = v.UpstreamType
		}

		sockets = append(sockets, socket)
	}

	time.Sleep(3 * time.Second)
	return sockets
}
