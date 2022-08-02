package models

type LoginResponse struct {
	Token string `json:"token"`
	MFA   bool   `json:"require_mfa"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterForm struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Sshkey   string `json:"sshkey"`
}
type LoginForm struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type MfaForm struct {
	Code string `json:"code"`
}

type LoginRefresh struct {
}

type TokenForm struct {
	Token string `json:"token"`
	MFA   bool   `json:"require_mfa"`
}

type SessionTokenForm struct {
	Token string `json:"token"`
	MFA   bool   `json:"require_mfa"`
	State string `json:"state"`
}

type SwitchOrgRequest struct {
	OrgName string `json:"org_name"`
}

type SwitchOrgResponse struct {
	Token   string `json:"token"`
	OrgName string `json:"org_name"`
	OrgID   string `json:"org_id"`
}

type SshCsr struct {
	SSHPublicKey  string `json:"ssh_public_key"`
	SSHSignedCert string `json:"signed_ssh_cert,omitempty"`
}
