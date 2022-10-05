package models

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/mysocketio/mysocketctl-go/internal/enum"
)

type ClientResource struct {
	PrivateSocket bool     `json:"private_socket,omitempty"`
	IPAddress     string   `json:"ip_address,omitempty"`
	SocketType    string   `json:"socket_type,omitempty"`
	SocketName    string   `json:"socket_name,omitempty"`
	Description   string   `json:"description,omitempty"`
	SocketPorts   []int    `json:"socket_ports,omitempty"`
	Domains       []string `json:"domains,omitempty"`
}

func (c ClientResource) Hostname() string {
	return c.FirstDomain("")
}

func (c ClientResource) HasDomain(tryToFind string) bool {
	for _, domain := range c.Domains {
		if tryToFind == domain {
			return true
		}
	}
	return false
}

func (c ClientResource) FirstDomain(defaultValue string) string {
	domain := defaultValue
	if len(c.Domains) > 0 {
		domain = c.Domains[0]
	}
	return domain
}

func (c ClientResource) DomainsToString() string {
	re := regexp.MustCompile(`edge\.(?:staging\.)?mysocket\.io$`)
	var domainsNotOwnedByUs []string
	for _, domain := range c.Domains {
		if !re.MatchString(domain) {
			domainsNotOwnedByUs = append(domainsNotOwnedByUs, domain)
		}
	}
	if len(domainsNotOwnedByUs) > 0 {
		return strings.Join(domainsNotOwnedByUs, ", ")
	}
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
