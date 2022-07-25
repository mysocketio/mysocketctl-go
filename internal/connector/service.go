package connector

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/mysocketio/mysocketctl-go/internal/api"
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
	"github.com/mysocketio/mysocketctl-go/internal/connector/config"
	"github.com/mysocketio/mysocketctl-go/internal/connector/core"
	"github.com/mysocketio/mysocketctl-go/internal/connector/discover"
	"github.com/mysocketio/mysocketctl-go/internal/http"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type ConnectorService struct {
	cfg    config.Config
	logger *zap.Logger
}

func NewConnectorService(cfg config.Config, logger *zap.Logger) *ConnectorService {
	return &ConnectorService{cfg, logger}
}

func (c *ConnectorService) Start() error {
	log.Println("starting the connector service")

	ctx := context.Background()
	var accessToken string
	var err error

	if c.cfg.Credentials.Token != "" {
		log.Println("using token defined in config file")
		accessToken = c.cfg.Credentials.Token
	} else {
		log.Println("using token defined in mysocketio file")
		accessToken, err = http.GetToken()
	}

	if err != nil {
		return err
	}

	var plugins []discover.Discover
	if len(c.cfg.AwsGroups) > 0 {
		sess, err := session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
			Profile:           c.cfg.Connector.AwsProfile,
			Config: aws.Config{
				Region: &c.cfg.Connector.AwsRegion,
			},
		})

		if err != nil {
			fmt.Println("Error creating aws session:", err)
		}

		if sess != nil {
			ec2Discover := discover.NewEC2Discover(ec2.New(sess), c.cfg)
			plugins = append(plugins, ec2Discover)
		}
	}

	if len(c.cfg.DockerPlugin) > 0 {
		plugins = append(plugins, &discover.DockerFinder{})
	}

	if c.cfg.K8Plugin != nil {
		k8Discover := discover.NewK8Discover()
		if k8Discover != nil {
			plugins = append(plugins, k8Discover)
		}
	}

	// always load the static socket plugin
	plugins = append(plugins, &discover.StaticSocketFinder{})

	c.StartWithPlugins(ctx, c.cfg, accessToken, plugins)

	return nil
}

func (c *ConnectorService) StartWithPlugins(ctx context.Context, cfg config.Config, accessToken string, plugins []discover.Discover) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	g, groupCtx := errgroup.WithContext(ctx)
	mysocketAPI := api.NewAPI(accessToken)

	for _, discoverPlugin := range plugins {
		connectorCore := core.NewConnectorCore(c.logger, c.cfg, discoverPlugin, mysocketAPI)

		socketUpdateCh := make(chan []models.Socket, 1)

		c.StartSocketWorker(groupCtx, connectorCore, socketUpdateCh, g)
		c.StartDiscovery(groupCtx, connectorCore, socketUpdateCh, g)
		connectorCore.TunnelConnectJob(groupCtx, g)
	}

	if err := g.Wait(); err != nil {
		c.logger.Info("Program terminated", zap.Error(err))
	}

	return nil
}

func (c ConnectorService) Stop() error {
	log.Println("stopping the connector service")
	return nil
}

func (c *ConnectorService) StartSocketWorker(ctx context.Context, connectorCore *core.ConnectorCore, socketUpdateCh chan []models.Socket, group *errgroup.Group) {
	group.Go(func() error {
		for {
			select {
			case sockets := <-socketUpdateCh:
				c.logger.Info("receiving an update")
				connectorCore.HandleUpdates(ctx, sockets)
			case <-ctx.Done():
				return errors.New("context canceled")
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
}

func (c *ConnectorService) StartDiscovery(ctx context.Context, connectorCore *core.ConnectorCore, socketUpdateCh chan []models.Socket, group *errgroup.Group) {
	group.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return errors.New("context canceled")
			default:
				connectorCore.DiscoverNewSocketChanges(ctx, socketUpdateCh)
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
}
