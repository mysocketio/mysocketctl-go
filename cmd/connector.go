package cmd

import (
	"log"
	"os"
	"path/filepath"

	"github.com/mysocketio/mysocketctl-go/internal/connector"
	"github.com/mysocketio/mysocketctl-go/internal/connector/config"
	"github.com/spf13/cobra"
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
		var configPath string
		if connectorConfig != "" {
			configPath = connectorConfig
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("failed to get home dir : %v", err)
			}

			configPath = filepath.Join(home, ".mysocketio_connector_config")
		}

		parser := config.NewConfigParser()

		log.Printf("reading the config %v", configPath)
		cfg, err := parser.Parse(configPath)
		if err != nil {
			log.Fatal(err)
		}

		svc, err := config.StartSSMSession(cfg)
		if err != nil {
			log.Printf("failed to start ssm session : %v\n", err)
		}

		if svc != nil {
			if err := parser.LoadSSMInConfig(svc, cfg); err != nil {
				log.Printf("failed to load ssm config : %v\n", err)
			}
		}

		connector.NewConnectorService(*cfg).Start()
	},
}

var connectorStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "stop the connector",
	Run: func(cmd *cobra.Command, args []string) {
		connector.NewConnectorService(*config.NewConfig()).Stop()
	},
}

func init() {
	connectorStartCmd.Flags().StringVarP(&connectorConfig, "config", "", "", "setup configuration for connector command")
	connectorCmd.AddCommand(connectorStartCmd)
	connectorCmd.AddCommand(connectorStopCmd)
	rootCmd.AddCommand(connectorCmd)
}