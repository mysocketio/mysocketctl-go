package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	validConfig := Config{
		Credentials: Credentials{User: "my-aweseome-email@mysocket.io", Password: "AVeryLongAndSecurePassword", Token: ""},
		Connector:   Connector{Name: "my-awesome.connector", AwsRegion: "us-west-2", AwsProfile: ""},
		Sockets: SocketParams{
			map[string]SocketConfig{
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
			map[string]SocketConfig{
				"rds.us-east-2": {
					Host:                  "my-rds-instance.cluster-giberish.us-east-2.rds.amazonaws.com",
					Port:                  3306,
					Name:                  "",
					Type:                  "database",
					AllowedEmailAddresses: []string{"some-email01@domain.com"},
					AllowedEmailDomains:   []string{"mysocket.io", "some-other-domain.com"},
					UpstreamUser:          "fancy_db_user",
					UpstreamPassword:      "AVeryLongAndSecurePasswordThingyTokenLikeStuff",
					UpstreamType:          "mysql",
				},
			},
			map[string]SocketConfig{
				"ssh.connector.lab": {
					Host:                  "127.0.0.1",
					Port:                  22,
					Name:                  "",
					Type:                  "ssh",
					AllowedEmailAddresses: []string{"some-email01@domain.com"},
					AllowedEmailDomains:   []string{"mysocket.io", "some-other-domain.com"},
					UpstreamUser:          "",
					UpstreamPassword:      "",
					UpstreamType:          "",
				},
			},
		},
		AwsGroups: []ConnectorGroups{
			{
				Group:                 "infra_team",
				AllowedEmailDomains:   []string{"mysocket.io"},
				AllowedEmailAddresses: []string{"mysocket.io", "some-other-domain.com"},
				PrivateSocket:         false,
			},
		},
		DockerPlugin: []ConnectorGroups{
			{
				Group:                 "docker_team",
				AllowedEmailDomains:   []string{"mysocket.io"},
				AllowedEmailAddresses: []string{"mysocket.io", "some-other-domain.com"},
				PrivateSocket:         false,
			},
		},
		NetworkPlugin: []NetworkPlugin{
			{
				Scan_interval:         300,
				Group:                 "network_plugin",
				AllowedEmailDomains:   []string{"mysocket.io"},
				AllowedEmailAddresses: []string{"mysocket.io", "some-other-domain.com"},
				Networks: map[string]NetworkPluginNetwork{
					"my lan0": {
						Interfaces: []string{"eth0"},
						Ports:      []uint16{80, 443, 3306},
					},
				},
			},
		},
	}

	tests := []struct {
		name    string
		path    string
		want    *Config
		wantErr bool
	}{
		{
			name:    "happy_path",
			path:    "testdata/config.yml",
			want:    &validConfig,
			wantErr: false,
		},
		{
			name:    "error parsing configuration",
			path:    "invalid_testdata_dir/",
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		viper.Reset()
		t.Run(tt.name, func(t *testing.T) {
			ConfigParser := NewConfigParser()
			got, err := ConfigParser.Parse(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr error
	}{
		{
			name:    "valid_config",
			cfg:     &Config{Connector: Connector{Name: "my-awesome-connector"}},
			wantErr: nil,
		},
		{
			name:    "invalid_name",
			cfg:     &Config{Connector: Connector{Name: "my awesome/connector.lab.mysocket.io"}},
			wantErr: ErrInvalidConnectorName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()

			assert.Equal(t, tt.wantErr, err)
		})
	}
}
