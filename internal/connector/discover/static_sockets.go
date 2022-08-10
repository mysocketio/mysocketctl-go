package discover

import (
	"context"
	"reflect"
	"time"

	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/connector/config"
)

type StaticSocketFinder struct{}

var _ Discover = (*StaticSocketFinder)(nil)

func (s *StaticSocketFinder) SkipRun(ctx context.Context, cfg config.Config, state DiscoverState) bool {
	return false
}

func (s *StaticSocketFinder) Find(ctx context.Context, cfg config.Config, state DiscoverState) ([]models.Socket, error) {
	time.Sleep(30 * time.Second)

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
			socket.UpstreamHttpHostname = v.UpstreamHttpHostname

			if socket.PrivateSocket {
				socket.Dnsname = socket.Name
			}

			socket.UpstreamType = v.UpstreamType
		}

		sockets = append(sockets, socket)
	}

	return sockets, nil
}

func (s *StaticSocketFinder) Name() string {
	return reflect.TypeOf(s).Elem().Name()
}
