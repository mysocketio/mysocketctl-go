package core

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/mysocketio/mysocketctl-go/internal/api"
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/connector/config"
	"github.com/mysocketio/mysocketctl-go/internal/connector/discover"
	"github.com/mysocketio/mysocketctl-go/internal/http"
	"github.com/mysocketio/mysocketctl-go/internal/ssh"
)

type ConnectorCore struct {
	discovery   discover.Discover
	cfg         config.Config
	mysocketAPI *api.API

	numberOfRuns     int64
	connectedSockets map[string]models.Socket
	discoverState    discover.DiscoverState
	wg               sync.WaitGroup
	lock             sync.RWMutex
}

func NewConnectorCore(cfg config.Config, discovery discover.Discover, mysocketAPI *api.API) *ConnectorCore {
	connectedSockets := make(map[string]models.Socket)
	discoverState := discover.DiscoverState{
		State:     make(map[string]interface{}),
		RunsCount: 0,
	}

	return &ConnectorCore{discovery: discovery, cfg: cfg, mysocketAPI: mysocketAPI, connectedSockets: connectedSockets, discoverState: discoverState}
}

func (c *ConnectorCore) IsSocketConnected(key string) bool {
	_, ok := c.connectedSockets[key]
	return ok
}

func (c *ConnectorCore) Handler(ctx context.Context, sockets []models.Socket) error {
	c.wg.Add(len(sockets))
	for _, socket := range sockets {
		go c.TunnelConnnect(ctx, socket)
	}
	c.wg.Wait()

	log.Println("Terminating Program")
	return nil
}

func (c *ConnectorCore) TunnelConnnect(ctx context.Context, socket models.Socket) error {
	// improve the error handling
	userID, _, err := http.GetUserIDFromAccessToken(c.mysocketAPI.AccessToken)
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
		log.Println("tunnel is empty, cannot connect to a tunnel")
		return err
	}

	tunnel := socket.Tunnels[0]
	c.lock.Lock()
	c.connectedSockets[socket.ConnectorData.Key()] = socket
	c.lock.Unlock()

	err = ssh.SshConnect(*userID, socket.SocketID, tunnel.TunnelID, socket.ConnectorData.Port, socket.ConnectorData.TargetHostname, "", "", "", false, org.Certificates["ssh_public_key"], c.mysocketAPI.AccessToken)
	if err != nil {
		c.lock.Lock()
		delete(c.connectedSockets, socket.ConnectorData.Key())
		c.lock.Unlock()
		return err
	}

	log.Println("connected")

	return nil
}

func (c *ConnectorCore) DiscoverNewSocketChanges(ctx context.Context, ch chan []models.Socket) {
	c.discoverState.RunsCount = c.numberOfRuns

	if c.discovery.SkipRun(ctx, c.cfg, c.discoverState) {
		return
	}

	sockets := c.discovery.Find(ctx, c.cfg, c.discoverState)
	for i, s := range sockets {
		s.BuildConnectorDataAndTags(c.cfg.Connector.Name)
		sockets[i] = s
	}

	atomic.AddInt64(&c.numberOfRuns, 1)
	ch <- sockets
}

func (c *ConnectorCore) SocketsCoreHandler(ctx context.Context, socketsToUpdate []models.Socket) ([]models.Socket, error) {
	var socketsToConnect []models.Socket

	discoveredSockets := socketsToUpdate

	localSocketsMap := make(map[string]models.Socket)
	for i, socket := range discoveredSockets {
		socket.BuildConnectorData(c.cfg.Connector.Name)
		socket.Tags = socket.ConnectorData.Tags()
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

		if socket.ConnectorData != nil && socket.ConnectorData.Key() != "" {
			socketApiMap[socket.ConnectorData.Key()] = socket
		}

		// update socket in the list
		socketsFromApi[i] = socket
	}

	log.Printf("statics sockets found %v\n", len(localSocketsMap))
	log.Printf("api sockets found %v\n", len(socketsFromApi))

	if err := c.CheckSocketsToDelete(ctx, socketsFromApi, localSocketsMap); err != nil {
		return nil, err
	}

	socketsToConnect, errC := c.CheckSocketsToCreate(ctx, discoveredSockets, socketApiMap)
	if errC != nil {
		log.Println(errC)
		return nil, errC
	}

	log.Println("number of sockets to connect: ", len(socketsToConnect))
	return socketsToConnect, nil
}

func (c *ConnectorCore) CheckAndUpdateSocket(ctx context.Context, apiSocket, localSocket models.Socket) (*models.Socket, error) {
	if len(apiSocket.AllowedEmailAddresses) > 0 && len(localSocket.AllowedEmailAddresses) > 0 && reflect.DeepEqual(apiSocket.AllowedEmailAddresses, localSocket.AllowedEmailAddresses) {
		return &apiSocket, nil
	}

	if len(apiSocket.AllowedEmailDomains) > 0 && len(localSocket.AllowedEmailDomains) > 0 && reflect.DeepEqual(apiSocket.AllowedEmailDomains, localSocket.AllowedEmailDomains) {
		return &apiSocket, nil
	}

	if apiSocket.UpstreamHttpHostname != localSocket.UpstreamHttpHostname ||
		apiSocket.UpstreamUsername != localSocket.UpstreamUsername ||
		apiSocket.UpstreamType != localSocket.UpstreamType ||
		apiSocket.CloudAuthEnabled != localSocket.CloudAuthEnabled {

		apiSocket.AllowedEmailAddresses = localSocket.AllowedEmailAddresses
		apiSocket.AllowedEmailDomains = localSocket.AllowedEmailDomains
		apiSocket.UpstreamHttpHostname = localSocket.UpstreamHttpHostname
		apiSocket.UpstreamUsername = localSocket.UpstreamUsername
		apiSocket.UpstreamType = localSocket.UpstreamType
		apiSocket.CloudAuthEnabled = localSocket.CloudAuthEnabled
		apiSocket.Tags = localSocket.Tags

		err := c.mysocketAPI.UpdateSocket(ctx, apiSocket.SocketID, apiSocket)
		if err != nil {
			return nil, err
		}

		log.Println("socket updated")
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
			log.Printf("socket exists locally: %s", s.Name)

			// check if socket needs to be recreated
			if *s.ConnectorData != *apiSocket.ConnectorData {
				log.Println("socket data is different, so we are recreating the socket")

				_, err := c.RecreateSocket(ctx, apiSocket.SocketID, s)
				if err != nil {
					return err
				}
			}
		} else if apiSocket.ConnectorData.Name == c.cfg.Connector.Name {
			log.Printf("socket does not exists locally, deleting the socket %s", apiSocket.Name)
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

			createdSocket.BuildConnectorData(c.cfg.Connector.Name)

			socketsToConnect = append(socketsToConnect, *createdSocket)
		} else {
			updatedSocket, err := c.CheckAndUpdateSocket(ctx, apiSocket, localSocket)
			if err != nil {
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
