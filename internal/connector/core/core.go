package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"

	"github.com/mysocketio/mysocketctl-go/internal/api"
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/connector/config"
	"github.com/mysocketio/mysocketctl-go/internal/connector/discover"
	"github.com/mysocketio/mysocketctl-go/internal/http"
	"github.com/mysocketio/mysocketctl-go/internal/ssh"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type connectTunnelData struct {
	key    string
	socket models.Socket
	action string
}
type ConnectorCore struct {
	discovery   discover.Discover
	cfg         config.Config
	mysocketAPI api.API
	logger      *zap.Logger

	numberOfRuns int64
	// connectedSockets map[string]models.Socket
	discoverState discover.DiscoverState
	connectChan   chan connectTunnelData
	// connectedTunnels map[string]*ssh.Connection
	connectedTunnels *SyncMap
}

func NewConnectorCore(logger *zap.Logger, cfg config.Config, discovery discover.Discover, mysocketAPI api.API) *ConnectorCore {
	connectedTunnels := &SyncMap{}
	connectChan := make(chan connectTunnelData, 5)
	discoverState := discover.DiscoverState{
		State:     make(map[string]interface{}),
		RunsCount: 0,
	}

	return &ConnectorCore{connectedTunnels: connectedTunnels, connectChan: connectChan, logger: logger, discovery: discovery, cfg: cfg, mysocketAPI: mysocketAPI, discoverState: discoverState}
}

func (c *ConnectorCore) IsSocketConnected(key string) bool {
	session, ok := c.connectedTunnels.Get(key)
	if ok {
		if session.(*ssh.Connection).IsClosed() {
			return false
		}
	}

	return ok
}

func (c *ConnectorCore) TunnelConnnect(ctx context.Context, socket models.Socket) error {
	session := ssh.NewConnection(c.logger, ssh.WithRetry(3))
	c.connectedTunnels.m.Store(socket.ConnectorData.Key(), session)

	// improve the error handling
	userID, _, err := http.GetUserIDFromAccessToken(c.mysocketAPI.GetAccessToken())
	if err != nil {
		return err
	}

	org, err := c.mysocketAPI.GetOrganizationInfo(ctx)
	if err != nil {
		return err
	}

	//reload socket
	socketFromApi, err := c.mysocketAPI.GetSocket(ctx, socket.SocketID)
	if err != nil {
		return err
	}
	socket = *socketFromApi
	socket.BuildConnectorDataByTags()

	if len(socket.Tunnels) == 0 {
		c.logger.Info("tunnel is empty, cannot connect to a tunnel")
		return err
	}

	tunnel := socket.Tunnels[0]

	err = session.Connect(ctx, *userID, socket.SocketID, tunnel.TunnelID, socket.ConnectorData.Port, socket.ConnectorData.TargetHostname, "", "", "", false, org.Certificates["ssh_public_key"], c.mysocketAPI.GetAccessToken())
	if err != nil {
		c.connectedTunnels.Delete(socket.ConnectorData.Key())
		return err
	}

	return nil
}

func (c *ConnectorCore) HandleUpdates(ctx context.Context, sockets []models.Socket) error {
	sockets, err := c.SocketsCoreHandler(ctx, sockets)
	if err != nil {
		log.Printf("failed to check new sockets: %v", err)
		return err
	}

	for _, socket := range sockets {
		if !c.IsSocketConnected(socket.ConnectorData.Key()) {
			c.logger.Info("found new socket to connect")

			c.connectChan <- connectTunnelData{
				key:    socket.ConnectorData.Key(),
				socket: socket,
				action: "connect"}
		}
	}

	return nil
}

func (c *ConnectorCore) TunnelConnectJob(ctx context.Context, group *errgroup.Group) {
	group.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return errors.New("context canceled")
			case tunnelConnectData := <-c.connectChan:
				if tunnelConnectData.action == "connect" {
					group.Go(func() error {
						err := c.TunnelConnnect(ctx, tunnelConnectData.socket)
						if err != nil {
							c.logger.Error("error connecting to tunnel", zap.String("error", err.Error()))
						}

						return nil
					})
				}

				if tunnelConnectData.action == "disconnect" {
					if session, ok := c.connectedTunnels.Get(tunnelConnectData.key); ok {
						session.(*ssh.Connection).Close()
					}
				}
			}
		}
	})
}

func (c *ConnectorCore) DiscoverNewSocketChanges(ctx context.Context, ch chan []models.Socket) {
	c.discoverState.RunsCount = c.numberOfRuns

	if c.discovery.SkipRun(ctx, c.cfg, c.discoverState) {
		return
	}

	sockets, err := c.discovery.Find(ctx, c.cfg, c.discoverState)
	if err != nil {
		c.logger.Error("error discovering new sockets", zap.Error(err))
		return
	}

	for i, s := range sockets {
		s.BuildConnectorDataAndTags(c.cfg.Connector.Name)
		sockets[i] = s
	}

	atomic.AddInt64(&c.numberOfRuns, 1)
	ch <- sockets
}

func (c *ConnectorCore) SocketsCoreHandler(ctx context.Context, socketsToUpdate []models.Socket) ([]models.Socket, error) {
	logger := c.logger.With(zap.String("plugin_name", c.discovery.Name()))
	var socketsToConnect []models.Socket

	discoveredSockets := socketsToUpdate

	// boostrap sockets coming from the discovery
	localSocketsMap := make(map[string]models.Socket)
	for i, socket := range discoveredSockets {
		socket.PluginName = c.discovery.Name()
		socket.SanitizeName()
		socket.BuildConnectorData(c.cfg.Connector.Name)
		socket.Tags = socket.ConnectorData.Tags()
		socket.SetupTypeAndUpstreamTypeByPortOrTags()
		localSocketsMap[socket.ConnectorData.Key()] = socket

		// update socket in the list
		discoveredSockets[i] = socket
	}

	socketsFromApi, err := c.mysocketAPI.GetSockets(ctx)
	if err != nil {
		return nil, err
	}

	socketApiMap := make(map[string]models.Socket)
	for i, socket := range socketsFromApi {
		socket.BuildConnectorDataByTags()
		// filter api sockets by connector name
		if socket.ConnectorData != nil && socket.ConnectorData.Key() != "" {
			socketApiMap[socket.ConnectorData.Key()] = socket
		}

		// update socket in the list
		socketsFromApi[i] = socket
	}

	logger.Info("sockets found",
		zap.Int("local connector sockets", len(discoveredSockets)),
		zap.Int("api sockets", len(socketsFromApi)),
		zap.Int("connected sockets", c.connectedTunnels.Len()))

	if err := c.CheckSocketsToDelete(ctx, socketsFromApi, localSocketsMap); err != nil {
		return nil, err
	}

	socketsToConnect, errC := c.CheckSocketsToCreate(ctx, discoveredSockets, socketApiMap)
	if errC != nil {
		logger.Error("error checking sockets to create", zap.Error(errC))
		return nil, errC
	}

	logger.Info("number of sockets to connect: ", zap.Int("sockets to connect", len(socketsToConnect)))
	return socketsToConnect, nil
}

func (c *ConnectorCore) CheckAndUpdateSocket(ctx context.Context, apiSocket, localSocket models.Socket) (*models.Socket, error) {
	check := stringSlicesEqual(apiSocket.AllowedEmailAddresses, localSocket.AllowedEmailAddresses) &&
		stringSlicesEqual(localSocket.AllowedEmailAddresses, apiSocket.AllowedEmailAddresses) &&
		stringSlicesEqual(apiSocket.AllowedEmailDomains, localSocket.AllowedEmailDomains) &&
		stringSlicesEqual(localSocket.AllowedEmailDomains, apiSocket.AllowedEmailDomains)

	if !check || apiSocket.UpstreamHttpHostname != localSocket.UpstreamHttpHostname ||
		apiSocket.UpstreamUsername != localSocket.UpstreamUsername ||
		apiSocket.UpstreamType != localSocket.UpstreamType {

		apiSocket.AllowedEmailAddresses = localSocket.AllowedEmailAddresses
		apiSocket.AllowedEmailDomains = localSocket.AllowedEmailDomains
		apiSocket.UpstreamHttpHostname = localSocket.UpstreamHttpHostname
		apiSocket.UpstreamUsername = localSocket.UpstreamUsername
		apiSocket.UpstreamType = ""
		apiSocket.Tags = localSocket.Tags

		err := c.mysocketAPI.UpdateSocket(ctx, apiSocket.SocketID, apiSocket)
		if err != nil {
			return nil, err
		}

		log.Printf("socket updated from local to api %v", apiSocket.Name)
	}

	return &apiSocket, nil
}

func (c *ConnectorCore) RecreateSocket(ctx context.Context, socketID string, localSocket models.Socket) (*models.Socket, error) {
	err := c.mysocketAPI.DeleteSocket(ctx, socketID)
	if err != nil {
		return nil, err
	}

	createdSocket, err := c.CreateSocketAndTunnel(ctx, &localSocket)
	if err != nil {
		return nil, err
	}

	createdSocket.BuildConnectorDataByTags()
	return createdSocket, nil
}

func (c *ConnectorCore) CheckSocketsToDelete(ctx context.Context, socketsFromApi []models.Socket, localSocketsMap map[string]models.Socket) error {
	for _, apiSocket := range socketsFromApi {
		//skip not connector sockets
		if apiSocket.ConnectorData != nil && apiSocket.ConnectorData.Key() == "" {
			continue
		}

		if s, ok := localSocketsMap[apiSocket.ConnectorData.Key()]; ok {
			// check if socket needs to be recreated
			if *s.ConnectorData != *apiSocket.ConnectorData {
				c.logger.Info("socket data is different, so we are recreating the socket",
					zap.String("plugin_name", c.discovery.Name()),
					zap.Any("local connector data", apiSocket.ConnectorData),
					zap.Any("connector data", s.ConnectorData),
				)

				createdSocket, err := c.RecreateSocket(ctx, apiSocket.SocketID, s)
				if err != nil {
					return err
				}
				localSocketsMap[apiSocket.ConnectorData.Key()] = *createdSocket
			}
		} else if apiSocket.ConnectorData.Connector == c.cfg.Connector.Name && apiSocket.ConnectorData.PluginName == c.discovery.Name() {
			c.logger.Info("socket does not exists locally, deleting the socket ",
				zap.String("plugin_name", c.discovery.Name()),
				zap.String("name", apiSocket.Name),
				zap.String("key", apiSocket.ConnectorData.Key()))

			// close tunnel connection before deleting the socket
			c.connectChan <- connectTunnelData{
				key:    apiSocket.ConnectorData.Key(),
				socket: apiSocket,
				action: "disconnect"}

			err := c.mysocketAPI.DeleteSocket(ctx, apiSocket.SocketID)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *ConnectorCore) CheckSocketsToCreate(ctx context.Context, localSockets []models.Socket, socketsFromApiMap map[string]models.Socket) ([]models.Socket, error) {
	var socketsToConnect []models.Socket

	for _, localSocket := range localSockets {
		if apiSocket, ok := socketsFromApiMap[localSocket.ConnectorData.Key()]; !ok {
			log.Printf("creating a socket: %s", localSocket.Name)

			createdSocket, err := c.CreateSocketAndTunnel(ctx, &localSocket)
			if err != nil {
				return nil, err
			}

			createdSocket.PluginName = c.discovery.Name()
			createdSocket.BuildConnectorData(c.cfg.Connector.Name)

			socketsToConnect = append(socketsToConnect, *createdSocket)
		} else {
			updatedSocket, err := c.CheckAndUpdateSocket(ctx, apiSocket, localSocket)
			if err != nil {
				c.logger.Info("error updating the socket", zap.String("error", err.Error()))
				return nil, err
			}

			socketsToConnect = append(socketsToConnect, *updatedSocket)
		}
	}
	return socketsToConnect, nil
}

func (c *ConnectorCore) CreateSocketAndTunnel(ctx context.Context, s *models.Socket) (*models.Socket, error) {
	privateSocket := s.PrivateSocket
	if s.PrivateSocket {
		s.PrivateSocket = false
	}

	if s.Description == "" {
		s.Description = fmt.Sprintf("created by %s", c.cfg.Connector.Name)
	}

	createdSocket, err := c.mysocketAPI.CreateSocket(ctx, s)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	tunnel, err := c.mysocketAPI.CreateTunnel(ctx, createdSocket.SocketID)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	createdSocket.Tunnels = append(createdSocket.Tunnels, *tunnel)

	// if socket is private we should use the name of the socket as a custom domains
	// to be accessible from the outside
	if privateSocket {
		createdSocket.Dnsname = createdSocket.Name
		createdSocket.CustomDomains = append(createdSocket.CustomDomains, createdSocket.Dnsname)
		createdSocket.PrivateSocket = true
		createdSocket.UpstreamType = ""
		err = c.mysocketAPI.UpdateSocket(ctx, createdSocket.SocketID, *createdSocket)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
	}

	return createdSocket, nil
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
