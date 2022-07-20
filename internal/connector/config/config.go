package config

import (
	"encoding/json"
	"fmt"
	"log"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	"github.com/spf13/viper"
)

type SocketConfig struct {
	Host                  string
	Port                  int
	Name                  string
	Type                  string
	Description           string
	AllowedEmailAddresses []string `mapstructure:"allowed_email_addresses"`
	AllowedEmailDomains   []string `mapstructure:"allowed_email_domains"`
	UpstreamUser          string   `mapstructure:"upstream_user"`
	UpstreamPassword      string   `mapstructure:"upstream_password"`
	UpstreamType          string   `mapstructure:"upstream_type"`
	PrivateSocket         bool     `mapstructure:"private_socket"`
	DatabaseCredentials   string   `mapstructure:"database_credentials"`
}

type Credentials struct {
	Username string
	Password string
	Token    string
}

type AwsGroups struct {
	Group                 string
	AllowedEmailAddresses []string `mapstructure:"allowed_email_addresses"`
	AllowedEmailDomains   []string `mapstructure:"allowed_email_domains"`
	PrivateSocket         bool     `mapstructure:"private_socket"`
}

type K8Plugin struct {
	Group                 string
	Namespace             string
	AllowedEmailAddresses []string `mapstructure:"allowed_email_addresses"`
	AllowedEmailDomains   []string `mapstructure:"allowed_email_domains"`
	PrivateSocket         bool     `mapstructure:"private_socket"`
}

type Connector struct {
	Name         string
	AwsRegion    string `mapstructure:"aws-region"`
	SSMAwsRegion string `mapstructure:"ssm-aws-region"`
	AwsProfile   string `mapstructure:"aws-profile"`
}

type SocketParams []map[string]SocketConfig

type Config struct {
	Credentials Credentials
	Sockets     SocketParams
	Connector   Connector
	AwsGroups   []AwsGroups `mapstructure:"aws_groups"`
	K8Plugin    []K8Plugin  `mapstructure:"k8_plugin"`
}

func NewConfig() *Config {
	return &Config{}
}

type ConfigParser struct {
}

func NewConfigParser() *ConfigParser {
	return &ConfigParser{}
}

func (c *ConfigParser) Parse(configPath string) (*Config, error) {
	viper.SetConfigType("yaml")
	viper.AddConfigPath(path.Dir(configPath))
	viper.SetConfigFile(configPath)

	err := viper.ReadInConfig()
	if err != nil {
		return nil, err
	}

	var cfg Config

	err = viper.Unmarshal(&cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *ConfigParser) LoadSSMInConfig(ssmAPI ssmiface.SSMAPI, cfg *Config) error {
	for _, socketMap := range cfg.Sockets {
		for k, v := range socketMap {
			if strings.HasPrefix(v.DatabaseCredentials, "aws:ssm:") {
				jsonCreds := SetupSSMField(ssmAPI, v.DatabaseCredentials)

				var mapCreds map[string]interface{}
				err := json.Unmarshal([]byte(jsonCreds), &mapCreds)
				if err != nil {
					return err
				}
				v.UpstreamUser = fmt.Sprint(mapCreds["username"])
				v.UpstreamPassword = fmt.Sprint(mapCreds["password"])

				if value, ok := mapCreds["engine"]; ok {
					v.UpstreamType = fmt.Sprint(value)
				}

				if value, ok := mapCreds["type"]; ok {
					v.UpstreamType = fmt.Sprint(value)
				}

				v.Host = fmt.Sprint(mapCreds["host"])
			}

			if strings.HasPrefix(v.UpstreamPassword, "aws:ssm:") {
				v.UpstreamPassword = SetupSSMField(ssmAPI, v.UpstreamPassword)
			}

			if strings.HasPrefix(v.UpstreamType, "aws:ssm:") {
				v.UpstreamType = SetupSSMField(ssmAPI, v.UpstreamType)
			}

			if strings.HasPrefix(v.UpstreamUser, "aws:ssm:") {
				v.UpstreamUser = SetupSSMField(ssmAPI, v.UpstreamUser)
			}

			if strings.HasPrefix(v.Host, "aws:ssm:") {
				v.Host = SetupSSMField(ssmAPI, v.Host)
			}

			socketMap[k] = v
		}
	}

	if strings.HasPrefix(cfg.Credentials.Username, "aws:ssm:") {
		cfg.Credentials.Username = SetupSSMField(ssmAPI, cfg.Credentials.Username)
	}

	if strings.HasPrefix(cfg.Credentials.Token, "aws:ssm:") {
		cfg.Credentials.Token = SetupSSMField(ssmAPI, cfg.Credentials.Token)
	}

	if strings.HasPrefix(cfg.Credentials.Password, "aws:ssm:") {
		cfg.Credentials.Password = SetupSSMField(ssmAPI, cfg.Credentials.Password)
	}

	return nil
}

func FetchFromSSM(svc ssmiface.SSMAPI, param string) (*ssm.GetParameterOutput, error) {
	results, err := svc.GetParameter(&ssm.GetParameterInput{
		Name:           aws.String(param),
		WithDecryption: aws.Bool(true),
	})

	return results, err
}

func StartSSMSession(cfg *Config) (ssmiface.SSMAPI, error) {
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Profile:           cfg.Connector.AwsProfile,
		Config: aws.Config{
			Region: &cfg.Connector.SSMAwsRegion,
		},
	})
	log.Printf("loading the ssm with: %s %s", cfg.Connector.AwsProfile, cfg.Connector.SSMAwsRegion)

	if err != nil {
		log.Printf("failed to create aws session: %v", err)
		return nil, err
	}

	return ssm.New(sess), nil
}

func SetupSSMField(svc ssmiface.SSMAPI, key string) string {
	spllitedKey := strings.Split(key, "aws:ssm:")
	output, err := FetchFromSSM(svc, spllitedKey[1])
	if err != nil {
		log.Printf("we couldn't fetch the key %v from ssm: %v\n", spllitedKey, err)
		return ""
	}

	if output != nil && output.Parameter != nil && output.Parameter.Value != nil {
		return *output.Parameter.Value
	}

	return ""
}
