package models

type LoginResponse struct {
	Token string `json:"token"`
	MFA   bool   `json:"require_mfa"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
