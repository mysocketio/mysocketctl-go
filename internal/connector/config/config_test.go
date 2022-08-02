package config

import (
	"reflect"
	"testing"

	"github.com/spf13/viper"
)

func TestParse(t *testing.T) {
	validConfig := Config{
		Credentials: Credentials{Username: "", Password: "AVeryLongAndSecurePassword", Token: ""},
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

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}
