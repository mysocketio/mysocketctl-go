package discover

import (
	"context"
	"log"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/mitchellh/mapstructure"
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/connector/config"
	"k8s.io/utils/strings/slices"
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

	// Let's determine if the connector runs in a docker container, and if so, what network id.
	connectorNetworkId, connectorGwIp, err := s.findNetworkID(containers)
	if err != nil {
		println("Error while trying to determine Network ID: ", err)
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
						ip := s.extractIPAddress(container.NetworkSettings.Networks, connectorNetworkId, connectorGwIp)

						// Now determine the port
						// First check if it is defined in the labels, otherwise we'll take it from Docker ports
						metadataPort := 0
						metadataPort, _ = strconv.Atoi(mySocketMetadata.Port)
						port := uint16(metadataPort)

						// Check what port we should return.
						// We default to the Private port.
						// But If we detect we run between networks, we should overwrite it to use the exposed port

						if connectorGwIp == ip {
							// This means, connector runs in a container, and is in a different namespace
							// So we assume no routing between networks, lets use
							port = s.extractPort(container.Ports, "public")
						}

						if port == 0 {
							// Not in label, so let's guess from the docker port
							port = s.extractPort(container.Ports, "private")
						}

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
			if len(kv) >= 2 {
				labels[kv[0]] = kv[1]
			}

		}
	}

	data := SocketData{}
	mapstructure.Decode(labels, &data)

	return data
}

func (s *DockerFinder) findNetworkID(containers []types.Container) (string, string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}
	var macAddresses []string
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" {
			macAddresses = append(macAddresses, a)
		}
	}

	// Now we have a list of mac addresses.
	// Let's see if there are any container namespaces with that mac
	for _, container := range containers {
		for _, value := range container.NetworkSettings.Networks {
			if value.MacAddress != "" {
				if slices.Contains(macAddresses, value.MacAddress) {
					return value.NetworkID, value.Gateway, nil
				}
			}
		}
	}
	return "", "", nil

}
func (s *DockerFinder) extractIPAddress(networkSettings map[string]*network.EndpointSettings, connectorNetworkId string, connectorGwIp string) string {

	if connectorNetworkId != "" {
		// This means the connector likely run in a container.
		for _, value := range networkSettings {
			if value.NetworkID == connectorNetworkId {
				// This means we're in the same network.
				// So we can retunr the private IP

				if value.IPAddress != "" {
					return value.IPAddress
				}
			}
		}

		// If we get here, then we didnt run the same network.. so we should return the default GW IP of the connector
		for _, value := range networkSettings {
			// This means we're in the same network.
			// So we can retunr the private IP
			if value.IPAddress != "" {
				return connectorGwIp
			}
		}
	}
	// Otherwise fall through, this means we likely run on the host and not in a contaoiner
	// and just return the private IP, Could probably also be 127.0.0.1
	for _, value := range networkSettings {
		if value.IPAddress != "" {
			return value.IPAddress
		}
	}

	return ""
}

func (s *DockerFinder) extractPort(ports []types.Port, portType string) uint16 {
	// First try to find a port that is linked to an IP
	// Sometimes this field is empty, which is odd.
	re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)

	if portType == "public" {
		for _, p := range ports {
			if p.Type == "tcp" && re.MatchString(p.IP) && p.PublicPort > 0 {
				return p.PublicPort
			}
		}
	} else {
		for _, p := range ports {
			if p.Type == "tcp" && re.MatchString(p.IP) && p.PrivatePort > 0 {
				return p.PrivatePort
			}
		}
	}
	// fall through
	// Otherwise return the first private port, even if IP is empty
	for _, p := range ports {
		if p.Type == "tcp" && p.PrivatePort > 0 {
			return p.PrivatePort
		}
	}

	return 0
}

func (s *DockerFinder) Name() string {
	return reflect.TypeOf(s).Elem().Name()
}
