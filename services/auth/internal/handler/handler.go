package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Shreyash019/chaotic-good/services/auth/internal/model"
	"github.com/Shreyash019/chaotic-good/services/auth/internal/service"
)

type AuthHandler struct {
	authService service.IAuthService
}

func NewAuthHandler(authService service.IAuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req model.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	if err := h.authService.Register(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User registered successfully",
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	resp, refreshToken, err := h.authService.Login(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Set refresh token as HttpOnly cookie — JS cannot read this (XSS safe)
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HttpOnly: true,  // not accessible via JS
		Secure:   false, // set true in production (HTTPS only)
		SameSite: http.SameSiteStrictMode,
		Path:     "/api/auth/refresh",
		MaxAge:   7 * 24 * 60 * 60, // 7 days
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Refresh reads the HttpOnly cookie and issues a new access token
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "Refresh token cookie missing", http.StatusUnauthorized)
		return
	}

	claims, err := h.authService.ValidateToken(cookie.Value)
	if err != nil {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	// Issue new access token via validate (reuse claims)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
}

func (h *AuthHandler) ValidateToken(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		http.Error(w, "Invalid authorization format. Use: Bearer <token>", http.StatusUnauthorized)
		return
	}

	claims, err := h.authService.ValidateToken(tokenString)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
}
