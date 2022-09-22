package models

type Policy struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	SocketIDs   []string `json:"socket_ids"`
}
