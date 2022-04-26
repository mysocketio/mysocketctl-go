package http

import (
	"fmt"
	"strings"

	"github.com/mysocketio/mysocketctl-go/internal/enum"
)

type registerForm struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Sshkey   string `json:"sshkey"`
}
type loginForm struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRefresh struct {
}

type TokenForm struct {
	Token string `json:"token"`
}

type SwitchOrgRequest struct {
	OrgName string `json:"org_name"`
}

type SwitchOrgResponse struct {
	Token   string `json:"token"`
	OrgName string `json:"org_name"`
	OrgID   string `json:"org_id"`
}

type ClientResource struct {
	PrivateSocket bool     `json:"private_socket,omitempty"`
	IPAddress     string   `json:"ip_address,omitempty"`
	SocketType    string   `json:"socket_type,omitempty"`
	SocketName    string   `json:"socket_name,omitempty"`
	SocketPorts   []int    `json:"socket_ports,omitempty"`
	Domains       []string `json:"domains,omitempty"`
}

func (c ClientResource) FirstDomain(defaultValue string) string {
	domain := defaultValue
	if len(c.Domains) > 0 {
		domain = c.Domains[0]
	}
	return domain
}

func (c ClientResource) DomainsToString() string {
	return strings.Join(c.Domains, ", ")
}

func (c ClientResource) Instruction() string {
	firstDomain := c.FirstDomain("<host>")

	var instruction string
	switch strings.ToLower(c.SocketType) {
	case enum.HTTPSocket, enum.HTTPSSocket:
		instruction = fmt.Sprintf("https://%s", firstDomain)
	case enum.SSHSocket:
		instruction = fmt.Sprintf("mysocketctl client ssh --username <username> --host %s", firstDomain)
	case enum.TLSSocket:
		instruction = fmt.Sprintf("mysocketctl client tls --host %s\n", firstDomain) +
			fmt.Sprintf("mysocketctl client tls --host %s --listener <local_port>", firstDomain)
	case enum.DatabaseSocket:
		instruction = fmt.Sprintf("mysocketctl client db --host %s", firstDomain)
	}
	return instruction
}

type ClientResources struct {
	RefreshHint        int              `json:"refresh_hint,omitempty"`
	Resources          []ClientResource `json:"resources,omitempty"`
	DefaultIPAddresses []string         `json:"ip_addresses,omitempty"`
}

type Account struct {
	Name         string        `json:"name,omitempty"`
	Email        string        `json:"email,omitempty"`
	UserID       string        `json:"user_id,omitempty"`
	SshUsername  string        `json:"user_name,omitempty"`
	SshKey       string        `json:"sshkey,omitempty"`
	Organization *Organization `json:"primary_organization"`
}

type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Socket struct {
	Tunnels               []Tunnel `json:"tunnels,omitempty"`
	Username              string   `json:"user_name,omitempty"`
	SocketID              string   `json:"socket_id,omitempty"`
	SocketTcpPorts        []int    `json:"socket_tcp_ports,omitempty"`
	Dnsname               string   `json:"dnsname,omitempty"`
	Name                  string   `json:"name,omitempty"`
	SocketType            string   `json:"socket_type,omitempty"`
	ProtectedSocket       bool     `json:"protected_socket"`
	ProtectedUsername     string   `json:"protected_username"`
	ProtectedPassword     string   `json:"protected_password"`
	CloudAuthEnabled      bool     `json:"cloud_authentication_enabled,omitempty"`
	AllowedEmailAddresses []string `json:"cloud_authentication_email_allowed_addressses,omitempty"`
	AllowedEmailDomains   []string `json:"cloud_authentication_email_allowed_domains,omitempty"`
	SSHCa                 string   `json:"ssh_ca,omitempty"`
	UpstreamUsername      string   `json:"upstream_username,omitempty"`
	UpstreamPassword      string   `json:"upstream_password,omitempty"`
	UpstreamHttpHostname  string   `json:"upstream_http_hostname,omitempty"`
	UpstreamType          string   `json:"upstream_type,omitempty"`
}

type Tunnel struct {
	TunnelID     string `json:"tunnel_id,omitempty"`
	LocalPort    int    `json:"local_port,omitempty"`
	TunnelServer string `json:"tunnel_server,omitempty"`
}

type SshCsr struct {
	SSHPublicKey  string `json:"ssh_public_key"`
	SSHSignedCert string `json:"signed_ssh_cert,omitempty"`
}

type OrganizationInfo struct {
	ID           string            `json:"id,omitempty"`
	Name         string            `json:"name,omitempty"`
	Certificates map[string]string `json:"certificate"`
}
