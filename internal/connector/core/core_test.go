package core

import (
	"context"
	"testing"

	"github.com/mysocketio/mysocketctl-go/internal/api/factories"
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/connector/config"
	"github.com/mysocketio/mysocketctl-go/internal/connector/discover"
	"github.com/mysocketio/mysocketctl-go/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

func TestConnectorCore_SocketsCoreHandler(t *testing.T) {
	socket := factories.SocketFactory.MustCreate().(*models.Socket)
	tunnel := &models.Tunnel{
		TunnelID:     "tunnel-id",
		LocalPort:    100,
		TunnelServer: "",
	}

	expectedSocket := *socket
	expectedSocket.Tunnels = append(expectedSocket.Tunnels, *tunnel)
	staticSocketPlugins := &discover.StaticSocketFinder{}
	cfg := validConfig()

	tests := []struct {
		name        string
		want        []models.Socket
		cfg         config.Config
		plugin      discover.Discover
		mysocketAPI func(*mocks.API)
		wantErr     bool
	}{
		{
			name:   "happy_path",
			want:   []models.Socket{expectedSocket},
			cfg:    cfg,
			plugin: staticSocketPlugins,
			mysocketAPI: func(api *mocks.API) {
				api.EXPECT().GetSockets(mock.Anything).Return([]models.Socket{}, nil)
				socket.PluginName = staticSocketPlugins.Name()
				socket.BuildConnectorDataAndTags(cfg.Connector.Name)
				api.EXPECT().CreateSocket(mock.Anything, mock.Anything).Return(socket, nil)
				api.EXPECT().CreateTunnel(mock.Anything, mock.Anything).Return(tunnel, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock API
			apiMock := &mocks.API{}
			tt.mysocketAPI(apiMock)

			c := NewConnectorCore(zap.NewNop(), tt.cfg, tt.plugin, apiMock)

			sockets, err := c.discovery.Find(context.Background(), tt.cfg, discover.DiscoverState{})
			if (err != nil) != tt.wantErr {
				t.Errorf("ConnectorCore.SocketsCoreHandler() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			got, err := c.SocketsCoreHandler(context.Background(), sockets)

			if tt.wantErr && err == nil {
				t.Errorf("ConnectorCore.SocketsCoreHandler() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for i, s := range tt.want {
				s.PluginName = tt.plugin.Name()
				s.BuildConnectorDataAndTags(tt.cfg.Connector.Name)
				tt.want[i] = s
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func validConfig() config.Config {
	validConfig := config.Config{
		Credentials: config.Credentials{Username: "", Password: "AVeryLongAndSecurePassword", Token: ""},
		Connector:   config.Connector{Name: "my-awesome.connector", AwsRegion: "us-west-2", AwsProfile: ""},
		Sockets: config.SocketParams{
			map[string]config.SocketConfig{
				"webserver.connector.lab": {
					Host:                  "127.0.0.1",
					Port:                  8000,
					Name:                  "",
					Type:                  "http",
					AllowedEmailAddresses: []string{"some-email01@domain.com"},
					AllowedEmailDomains:   []string{"mysocket.io", "some-other-domain.com"},
					UpstreamUser:          "",
					UpstreamPassword:      "",
					UpstreamType:          "",
				},
			},
		},
	}
	return validConfig
}
