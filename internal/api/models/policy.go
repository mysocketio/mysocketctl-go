package models

import (
	"time"
)

type Policy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	PolicyData  string    `json:"policy_data"`
	CreatedAt   time.Time `json:"created_at"`
	SocketIDs   []string  `json:"socket_ids"`
	Deleted     bool      `json:"deleted"`
}
