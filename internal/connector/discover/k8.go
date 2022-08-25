package discover

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/connector/config"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type K8Discover struct {
	clusterConfig *rest.Config
}

var _ Discover = (*K8Discover)(nil)

func NewK8Discover() *K8Discover {
	config, err := rest.InClusterConfig()
	if err != nil {
		fmt.Println("error creating cluster config:", err)
		return nil
	}

	return &K8Discover{clusterConfig: config}
}

func (s *K8Discover) SkipRun(ctx context.Context, cfg config.Config, state DiscoverState) bool {
	return false
}

func (s *K8Discover) Find(ctx context.Context, cfg config.Config, state DiscoverState) ([]models.Socket, error) {
	time.Sleep(10 * time.Second)

	clientset, err := kubernetes.NewForConfig(s.clusterConfig)
	if err != nil {
		fmt.Println("error creating k8 client:", err)
		return nil, err
	}

	var sockets []models.Socket

	for _, group := range cfg.K8Plugin {

		services, err := clientset.CoreV1().Services(group.Namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			fmt.Println("error listing services:", err)
			continue
		}

		for _, service := range services.Items {
			if _, ok := service.Annotations["mysocket.io/group"]; ok {
				if service.Annotations["mysocket.io/group"] == group.Group {

					socket := s.buildSocket(cfg.Connector.Name, group, service)
					sockets = append(sockets, *socket)
				}
			}
		}
	}

	return sockets, nil
}

func (s *K8Discover) buildSocket(connectorName string, group config.K8Plugin, service v1.Service) *models.Socket {
	socket := models.Socket{}
	socket.PolicyGroup = group.Group
	socket.InstanceId = string(service.UID)
	socket.TargetPort = int(service.Spec.Ports[0].Port)
	socket.TargetHostname = service.Spec.ClusterIP

	switch service.Annotations["mysocket.io/socketType"] {
	case "tcp":
		socket.SocketType = "tcp"
	case "http":
		socket.SocketType = "http"
	case "ssh":
		socket.SocketType = "ssh"
	case "database":
		socket.SocketType = "database"
	case "postgres":
		socket.SocketType = "database"
		socket.UpstreamType = "postgres"
	default:
		socket.SocketType = "tls"
	}

	enabled, ok := service.Annotations["mysocket.io/privateSocket"]
	if ok && enabled == "true" || group.PrivateSocket {
		socket.PrivateSocket = true
	}

	if _, ok = service.Annotations["mysocket.io/allowedEmailAddresses"]; ok {
		socket.AllowedEmailAddresses = strings.Split(service.Annotations["mysocket.io/allowedEmailAddresses"], ",")
	} else {
		socket.AllowedEmailAddresses = group.AllowedEmailAddresses
	}

	if _, ok = service.Annotations["mysocket.io/allowedEmailDomains"]; ok {
		socket.AllowedEmailDomains = strings.Split(service.Annotations["mysocket.io/allowedEmailDomains"], ",")
	} else {
		socket.AllowedEmailDomains = group.AllowedEmailDomains
	}

	name := fmt.Sprintf("%v-%v-%v", socket.SocketType, service.Name, connectorName)

	socket.Name = name
	if socket.PrivateSocket {
		socket.Dnsname = name
	}

	return &socket
}

func (s *K8Discover) Name() string {
	return reflect.TypeOf(s).Elem().Name()
}
