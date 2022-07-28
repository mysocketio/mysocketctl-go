package discover

import (
	"context"
	"log"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/mitchellh/mapstructure"
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/connector/config"
)

type SocketData struct {
	Port  string `mapstructure:"port"`
	Type  string
	Group string
	Host  string
}

type DockerFinder struct{}

var _ Discover = (*DockerFinder)(nil)

func (s *DockerFinder) SkipRun(ctx context.Context, cfg config.Config, state DiscoverState) bool {
	return false
}

func (s *DockerFinder) Find(ctx context.Context, cfg config.Config, state DiscoverState) ([]models.Socket, error) {
	time.Sleep(10 * time.Second)

	sockets := []models.Socket{}
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Println("Error creating docker client:", err)
		return nil, err
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})

	if err != nil {
		log.Println("Error getting containers:", err)
		return nil, err
	}

	for _, group := range cfg.DockerPlugin {
		for _, container := range containers {
			labels := container.Labels
			var instanceName string
			if len(labels) > 0 {
				instanceName = container.Names[0]
				instanceName = strings.Replace(instanceName, "/", "", -1)
			}
			for k, v := range labels {
				if k == "Name" && instanceName == "" {
					instanceName = v
				}
				if strings.HasPrefix(strings.ToLower(k), "mysocket") {
					mySocketMetadata := s.parseLabels(v)
					if mySocketMetadata.Group != "" && group.Group == mySocketMetadata.Group {
						ip := s.extractIPAddress(container.NetworkSettings.Networks)
						port := s.extractPort(container.Ports)

						if port == 0 {
							log.Println("Could not determine container Port... ignoring instance: ", instanceName)
							continue
						}
						if ip == "" {
							log.Println("Could not determine container IP... ignoring instance: ", instanceName)
							continue
						}

						sockets = append(sockets, s.buildSocket(cfg.Connector.Name, group, mySocketMetadata, container, instanceName, ip, port))
					}
				}
			}
		}
	}

	return sockets, nil
}

func (s *DockerFinder) buildSocket(connectorName string, group config.ConnectorGroups, socketData SocketData, instance types.Container, instanceName, ipAddress string, port uint16) models.Socket {
	socket := models.Socket{}
	socket.TargetPort = int(port)
	socket.PolicyGroup = group.Group
	socket.InstanceId = instance.ID

	socket.SocketType = socketData.Type
	socket.AllowedEmailAddresses = group.AllowedEmailAddresses
	socket.AllowedEmailDomains = group.AllowedEmailDomains
	if len(socket.AllowedEmailAddresses) > 0 || len(socket.AllowedEmailDomains) > 0 {
		socket.CloudAuthEnabled = true
	}

	socket.PrivateSocket = group.PrivateSocket

	socket.TargetHostname = socketData.Host
	if socket.TargetHostname == "" || socket.TargetHostname == "<nil>" {
		socket.TargetHostname = ipAddress
	}

	socket.Name = buildSocketName(instanceName, connectorName, socket.SocketType)
	if socket.PrivateSocket {
		socket.Dnsname = socket.Name
	}
	return socket
}

func (s *DockerFinder) parseLabels(label string) SocketData {
	labels := map[string]string{}
	for _, label := range strings.Split(label, ",") {
		label = strings.TrimSpace(label)
		if strings.Contains(label, "=") {
			kv := strings.Split(label, "=")
			labels[kv[0]] = kv[1]
		}
	}

	data := SocketData{}
	mapstructure.Decode(labels, &data)

	return data
}

func (s *DockerFinder) extractIPAddress(networkSettings map[string]*network.EndpointSettings) string {

	for _, value := range networkSettings {
		if value.IPAddress != "" {
			return value.IPAddress
		}
	}

	return ""
}

func (s *DockerFinder) extractPort(ports []types.Port) uint16 {
	re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)

	for _, p := range ports {
		if p.Type == "tcp" && re.MatchString(p.IP) {
			return p.PrivatePort
		}
	}

	return 0
}

func (s *DockerFinder) Name() string {
	return reflect.TypeOf(s).Elem().Name()
}
