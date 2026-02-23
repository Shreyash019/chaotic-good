package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shreyashkumar/funny-pipe/services/auth/internal/model"
)

type mockAuthSvc struct {
	registerErr  error
	loginResp    *model.AuthResponse
	loginRefresh string
	loginErr     error
	claims       *model.Claims
	validateErr  error
}

func (m *mockAuthSvc) Register(_ *model.RegisterRequest) error { return m.registerErr }
func (m *mockAuthSvc) Login(_ *model.LoginRequest) (*model.AuthResponse, string, error) {
	return m.loginResp, m.loginRefresh, m.loginErr
}
func (m *mockAuthSvc) ValidateToken(_ string) (*model.Claims, error) { return m.claims, m.validateErr }

func TestRegisterHandler_OK(t *testing.T) {
	h := NewAuthHandler(&mockAuthSvc{})
	body, _ := json.Marshal(model.RegisterRequest{Email: "a@b.com", Password: "pass"})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Register(rr, req)
	if rr.Code != http.StatusCreated { t.Errorf("expected 201, got %d: %s", rr.Code, rr.Body.String()) }
}

func TestRegisterHandler_MissingPassword(t *testing.T) {
	h := NewAuthHandler(&mockAuthSvc{})
	body, _ := json.Marshal(model.RegisterRequest{Email: "a@b.com"})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Register(rr, req)
	if rr.Code != http.StatusBadRequest { t.Errorf("expected 400, got %d", rr.Code) }
}

func TestLoginHandler_OK(t *testing.T) {
	svc := &mockAuthSvc{
		loginResp:    &model.AuthResponse{AccessToken: "tok", ExpiresIn: 900},
		loginRefresh: "refresh",
	}
	h := NewAuthHandler(svc)
	body, _ := json.Marshal(model.LoginRequest{Email: "a@b.com", Password: "pass"})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Login(rr, req)
	if rr.Code != http.StatusOK { t.Errorf("expected 200, got %d", rr.Code) }
	var resp model.AuthResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.AccessToken != "tok" { t.Errorf("expected tok, got %q", resp.AccessToken) }
	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "refresh_token" && c.HttpOnly { found = true }
	}
	if !found { t.Error("expected HttpOnly refresh_token cookie") }
}

func TestLoginHandler_BadCreds(t *testing.T) {
	h := NewAuthHandler(&mockAuthSvc{loginErr: errors.New("invalid credentials")})
	body, _ := json.Marshal(model.LoginRequest{Email: "a@b.com", Password: "bad"})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Login(rr, req)
	if rr.Code != http.StatusUnauthorized { t.Errorf("expected 401, got %d", rr.Code) }
}
