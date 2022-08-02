package models

type Account struct {
	Name         string        `json:"name,omitempty"`
	Email        string        `json:"email,omitempty"`
	UserID       string        `json:"user_id,omitempty"`
	SshUsername  string        `json:"user_name,omitempty"`
	SshKey       string        `json:"sshkey,omitempty"`
	Organization *Organization `json:"primary_organization"`
}
