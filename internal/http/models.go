package http

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
type tokenForm struct {
	Token string `json:"token"`
}

type Account struct {
	Name        string `json:"name,omitempty"`
	Email       string `json:"email,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	SshUsername string `json:"user_name,omitempty"`
	SshKey      string `json:"sshkey,omitempty"`
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
}

type Tunnel struct {
	TunnelID     string `json:"tunnel_id,omitempty"`
	LocalPort    int    `json:"local_port,omitempty"`
	TunnelServer string `json:"tunnel_server,omitempty"`
}
