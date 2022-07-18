package models

type Organization struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Certificates map[string]string `json:"certificate"`
}
