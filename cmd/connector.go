package cmd

import (
	"os"
	"path/filepath"

	"github.com/mysocketio/mysocketctl-go/internal/connector"
	"github.com/mysocketio/mysocketctl-go/internal/connector/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// connectorCmd represents the connector service
var connectorCmd = &cobra.Command{
	Use:   "connector",
	Short: "connector wrapper",
}

var connectorStartCmd = &cobra.Command{
	Use:   "start",
	Short: "start the connector",
	Run: func(cmd *cobra.Command, args []string) {
		log, _ := zap.NewProduction()
		defer log.Sync()

		var configPath string
		if connectorConfig != "" {
			configPath = connectorConfig
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatal("failed to get home dir", zap.String("error", err.Error()))
			}

			configPath = filepath.Join(home, ".mysocketio_connector_config")
		}

		parser := config.NewConfigParser()

		log.Info("reading the config", zap.String("config_path", configPath))
		cfg, err := parser.Parse(configPath)
		if err != nil {
			log.Fatal("failed to parse config", zap.String("error", err.Error()))
		}

		svc, err := config.StartSSMSession(cfg)
		if err != nil {
			log.Error("failed to start ssm session", zap.String("error", err.Error()))
		}

		if svc != nil {
			if err := parser.LoadSSMInConfig(svc, cfg); err != nil {
				log.Error("failed to load ssm config", zap.String("error", err.Error()))
			}
		}

		if err := connector.NewConnectorService(*cfg, log).Start(); err != nil {
			log.Error("failed to start connector", zap.String("error", err.Error()))
		}
	},
}

var connectorStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "stop the connector",
	Run: func(cmd *cobra.Command, args []string) {
		connector.NewConnectorService(*config.NewConfig(), nil).Stop()
	},
}

func init() {
	connectorStartCmd.Flags().StringVarP(&connectorConfig, "config", "", "", "setup configuration for connector command")
	connectorCmd.AddCommand(connectorStartCmd)
	connectorCmd.AddCommand(connectorStopCmd)
	rootCmd.AddCommand(connectorCmd)
}
