package handler

import (
	"encoding/json"
	"net/http"

	"github.com/Shreyash019/chaotic-good/services/user/internal/model"
	"github.com/Shreyash019/chaotic-good/services/user/internal/service"
)

type UserHandler struct {
	userService service.IUserService
}

func NewUserHandler(userService service.IUserService) *UserHandler {
	return &UserHandler{userService: userService}
}

// GetMe handles GET /me
func (h *UserHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID, email, ok := extractIdentity(r)
	if !ok {
		http.Error(w, "missing user identity headers", http.StatusUnauthorized)
		return
	}

	profile, err := h.userService.GetProfile(userID, email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, profile)
}

// UpdateMe handles PUT /me
func (h *UserHandler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := extractIdentity(r)
	if !ok {
		http.Error(w, "missing user identity headers", http.StatusUnauthorized)
		return
	}

	var req model.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" && req.Bio == "" {
		http.Error(w, "at least one field (name or bio) is required", http.StatusBadRequest)
		return
	}

	profile, err := h.userService.UpdateProfile(userID, &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, profile)
}

// DeleteMe handles DELETE /me
func (h *UserHandler) DeleteMe(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := extractIdentity(r)
	if !ok {
		http.Error(w, "missing user identity headers", http.StatusUnauthorized)
		return
	}

	if err := h.userService.DeleteProfile(userID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "account deleted"})
}

// GetByID handles GET /{id}
func (h *UserHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "user id is required", http.StatusBadRequest)
		return
	}

	profile, err := h.userService.GetProfile(id, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, profile)
}

func extractIdentity(r *http.Request) (userID, email string, ok bool) {
	userID = r.Header.Get("X-User-ID")
	email = r.Header.Get("X-User-Email")
	return userID, email, userID != ""
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}
