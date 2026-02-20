package model

import "time"

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"-"` // never expose password
	CreatedAt time.Time `json:"created_at"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	// RefreshToken is intentionally excluded — sent via HttpOnly cookie
}

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Exp    int64  `json:"exp"`
}
