package preference

import (
	"sort"
	"time"

	"github.com/mysocketio/mysocketctl-go/internal/enum"
)

type Data struct {
	Orgs              map[string]Org    `json:"orgs"`
	Sockets           map[string]Socket `json:"sockets"`
	PreferredTerminal string            `json:"preferred_terminal"`
	PathEnvConfigured bool              `json:"path_env_configured"`
}

type Org struct {
	ID        string    `json:"id"`
	Subdomain string    `json:"subdomain"`
	LastUsed  time.Time `json:"last_used"`
}

type Socket struct {
	DNSName        string    `json:"dns_name"`
	Username       string    `json:"username"`
	LastUsed       time.Time `json:"last_used"`
	SocketType     string    `json:"socket_type"`
	DatabaseName   string    `json:"database_name"`
	DatabaseClient string    `json:"database_client"`
}

func NewData() *Data {
	return &Data{
		Orgs:    make(map[string]Org),
		Sockets: make(map[string]Socket),
	}
}

func NewOrg(id string) *Org {
	return &Org{
		ID:       id,
		LastUsed: time.Now(),
	}
}

func NewSSHSocket(dnsName string) *Socket {
	return &Socket{
		DNSName:    dnsName,
		SocketType: enum.SSHSocket,
		LastUsed:   time.Now(),
	}
}

func NewDatabaseSocket(dnsName string) *Socket {
	return &Socket{
		DNSName:    dnsName,
		SocketType: enum.DatabaseSocket,
		LastUsed:   time.Now(),
	}
}

func Found(mayHaveFound interface{}) bool {
	switch v := mayHaveFound.(type) {
	case *Org:
		return v != nil
	case *Socket:
		return v != nil
	default:
		return false
	}
}

func (d *Data) Org(orgID string) *Org {
	if foundOrg, exists := d.Orgs[orgID]; exists {
		return &foundOrg
	}
	return NewOrg(orgID)
}

func (d *Data) SetOrg(input *Org) {
	id := input.ID

	if foundOrg, exists := d.Orgs[id]; exists {
		input = &foundOrg
	}

	input.LastUsed = time.Now()
	d.Orgs[id] = *input
}

func (d *Data) RecentlyUsedOrgs(howMany int) Orgs {
	var orgs []Org
	for _, org := range d.Orgs {
		if org.Subdomain != "" {
			orgs = append(orgs, org)
		}
	}
	// descending sort orgs list by last used time
	// most recently used orgs are at the top
	sort.Slice(orgs, func(i, j int) bool {
		return orgs[i].LastUsed.After(orgs[j].LastUsed)
	})
	if len(orgs) > howMany {
		return orgs[:howMany]
	}
	return orgs
}

func (d *Data) GetOrSuggestSocket(dnsName string, socketType string) *Socket {
	if socket := d.Socket(dnsName); socket != nil {
		return socket
	}
	return d.SuggestSocket(dnsName, socketType)
}

func (d *Data) Socket(dnsName string) *Socket {
	if socket, exists := d.Sockets[dnsName]; exists {
		return &socket
	}
	return nil
}

func (d *Data) SuggestSocket(dnsName, socketType string) *Socket {
	switch socketType {
	case enum.SSHSocket:
		topUsernames := make(map[string]int)
		for _, socket := range d.Sockets {
			if socket.SocketType == enum.SSHSocket {
				topUsernames[socket.Username]++
			}
		}

		var suggestedUsername string
		for username, score := range topUsernames {
			if score > topUsernames[suggestedUsername] {
				suggestedUsername = username
			}
		}

		if suggestedUsername == "" {
			return nil
		}
		return &Socket{
			DNSName:    dnsName,
			SocketType: socketType,
			Username:   suggestedUsername,
		}
	case enum.DatabaseSocket:
		topDBNames := make(map[string]int)
		topDBClients := make(map[string]int)
		for _, socket := range d.Sockets {
			if socket.SocketType == enum.DatabaseSocket {
				topDBNames[socket.DatabaseName]++
				topDBClients[socket.DatabaseClient]++
			}
		}

		var suggestedDBName, suggestedDBClient string
		for dbName, score := range topDBNames {
			if score > topDBNames[suggestedDBName] {
				suggestedDBName = dbName
			}
		}
		for dbClient, score := range topDBClients {
			if score > topDBClients[suggestedDBClient] {
				suggestedDBClient = dbClient
			}
		}

		if suggestedDBName == "" || suggestedDBClient == "" {
			return nil
		}
		return &Socket{
			DNSName:        dnsName,
			SocketType:     socketType,
			DatabaseName:   suggestedDBName,
			DatabaseClient: suggestedDBClient,
		}
	default:
		return nil
	}
}

func (d *Data) SetSocket(input *Socket) {
	dnsName := input.DNSName

	if foundSocket, exists := d.Sockets[dnsName]; exists {
		switch input.SocketType {
		case enum.SSHSocket:
			foundSocket.Username = input.Username
		case enum.DatabaseSocket:
			foundSocket.DatabaseName = input.DatabaseName
			foundSocket.DatabaseClient = input.DatabaseClient
		}
		input = &foundSocket
	}

	input.LastUsed = time.Now()
	d.Sockets[dnsName] = *input
}

type Orgs []Org

func (o Orgs) Subdomains() []string {
	var subdomains []string
	for _, org := range o {
		subdomains = append(subdomains, org.Subdomain)
	}
	return subdomains
}
