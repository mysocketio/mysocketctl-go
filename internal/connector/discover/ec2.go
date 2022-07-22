package discover

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/mitchellh/mapstructure"
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/connector/config"
)

type Ec2Discover struct {
	ec2API ec2iface.EC2API
}

type Ec2SocketData struct {
	Port  string `mapstructure:"port"`
	Type  string
	Group string
	Host  string
}

func NewEC2Discover(ec2API ec2iface.EC2API, cfg config.Config) *Ec2Discover {
	return &Ec2Discover{ec2API: ec2API}
}

func (s *Ec2Discover) SkipRun(ctx context.Context, cfg config.Config, state DiscoverState) bool {
	return false
}

func (s *Ec2Discover) Find(ctx context.Context, cfg config.Config, state DiscoverState) []models.Socket {
	// find all instance running in the configured region
	params := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("instance-state-name"),
				Values: []*string{
					aws.String("running"),
				},
			},
		},
	}

	res, _ := s.ec2API.DescribeInstances(params)

	var sockets []models.Socket

	for _, group := range cfg.AwsGroups {
		for _, i := range res.Reservations {
			for _, ti := range i.Instances {
				var instanceName string

				// check the instance name in the tags
				for _, t := range ti.Tags {
					if *t.Key == "Name" {
						instanceName = *t.Value
					}
				}

				for _, t := range ti.Tags {
					if strings.HasPrefix(*t.Key, "mysocket") {
						socketData := parseAwsDataTag(*t.Value)

						if socketData.Group == group.Group {
							socket := s.buildSocket(cfg.Connector.Name, group, socketData, *ti, instanceName)
							sockets = append(sockets, *socket)
						}
					}
				}
			}
		}
	}
	time.Sleep(10 * time.Second)
	return sockets
}

func (s *Ec2Discover) buildSocket(connectorName string, group config.AwsGroups, socketData Ec2SocketData, instance ec2.Instance, instanceName string) *models.Socket {
	socket := models.Socket{}
	socket.TargetPort, _ = strconv.Atoi(socketData.Port)
	socket.PolicyGroup = group.Group
	socket.InstanceId = *instance.InstanceId

	socket.SocketType = socketData.Type
	socket.AllowedEmailAddresses = group.AllowedEmailAddresses
	socket.AllowedEmailDomains = group.AllowedEmailDomains
	if len(socket.AllowedEmailAddresses) > 0 || len(socket.AllowedEmailDomains) > 0 {
		socket.CloudAuthEnabled = true
	}

	socket.PrivateSocket = group.PrivateSocket

	socket.TargetHostname = socketData.Host
	if socket.TargetHostname == "" || socket.TargetHostname == "<nil>" {
		socket.TargetHostname = *instance.PrivateIpAddress
	}

	socket.Name = buildSocketName(instanceName, connectorName, socket.SocketType)
	if socket.PrivateSocket {
		socket.Dnsname = socket.Name
	}
	return &socket
}

func buildSocketName(instanceName, connectorName, socketType string) string {
	s := strings.Replace(instanceName, "_", "-", -1)
	s = strings.Replace(s, ".", "-", -1)

	return fmt.Sprintf("%v-%v-%v", socketType, s, connectorName)
}

func parseAwsDataTag(tag string) Ec2SocketData {
	data := make(map[string]interface{})
	fields := strings.Split(tag, ",")
	for _, field := range fields {
		keyAndValue := strings.Split(field, "=")

		data[keyAndValue[0]] = keyAndValue[1]
	}

	ec2SocketData := Ec2SocketData{}
	mapstructure.Decode(data, &ec2SocketData)

	return ec2SocketData
}