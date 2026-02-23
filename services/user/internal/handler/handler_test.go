package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shreyashkumar/funny-pipe/services/user/internal/model"
)

type mockUserSvc struct {
	profile    *model.UserProfile
	profileErr error
	updateErr  error
	deleteErr  error
}

func (m *mockUserSvc) GetProfile(_, _ string) (*model.UserProfile, error) { return m.profile, m.profileErr }
func (m *mockUserSvc) UpdateProfile(_ string, _ *model.UpdateProfileRequest) (*model.UserProfile, error) {
	return m.profile, m.updateErr
}
func (m *mockUserSvc) DeleteProfile(_ string) error { return m.deleteErr }

func withHeaders(method, target string, body []byte) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Header.Set("X-User-ID", "u1")
	req.Header.Set("X-User-Email", "u@t.com")
	return req
}

func TestGetMe_OK(t *testing.T) {
	h := NewUserHandler(&mockUserSvc{profile: &model.UserProfile{ID: "u1"}})
	rr := httptest.NewRecorder()
	h.GetMe(rr, withHeaders(http.MethodGet, "/me", nil))
	if rr.Code != http.StatusOK { t.Errorf("expected 200, got %d", rr.Code) }
}

func TestGetMe_NoAuth(t *testing.T) {
	h := NewUserHandler(&mockUserSvc{})
	rr := httptest.NewRecorder()
	h.GetMe(rr, httptest.NewRequest(http.MethodGet, "/me", nil))
	if rr.Code != http.StatusUnauthorized { t.Errorf("expected 401, got %d", rr.Code) }
}

func TestUpdateMe_OK(t *testing.T) {
	h := NewUserHandler(&mockUserSvc{profile: &model.UserProfile{ID: "u1", Name: "Bob"}})
	body, _ := json.Marshal(model.UpdateProfileRequest{Name: "Bob"})
	rr := httptest.NewRecorder()
	h.UpdateMe(rr, withHeaders(http.MethodPut, "/me", body))
	if rr.Code != http.StatusOK { t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String()) }
}

func TestUpdateMe_EmptyFields(t *testing.T) {
	h := NewUserHandler(&mockUserSvc{})
	body, _ := json.Marshal(model.UpdateProfileRequest{})
	rr := httptest.NewRecorder()
	h.UpdateMe(rr, withHeaders(http.MethodPut, "/me", body))
	if rr.Code != http.StatusBadRequest { t.Errorf("expected 400, got %d", rr.Code) }
}

func TestUpdateMe_NotFound(t *testing.T) {
	h := NewUserHandler(&mockUserSvc{updateErr: errors.New("not found")})
	body, _ := json.Marshal(model.UpdateProfileRequest{Name: "X"})
	rr := httptest.NewRecorder()
	h.UpdateMe(rr, withHeaders(http.MethodPut, "/me", body))
	if rr.Code != http.StatusNotFound { t.Errorf("expected 404, got %d", rr.Code) }
}

func TestDeleteMe_OK(t *testing.T) {
	h := NewUserHandler(&mockUserSvc{})
	rr := httptest.NewRecorder()
	h.DeleteMe(rr, withHeaders(http.MethodDelete, "/me", nil))
	if rr.Code != http.StatusOK { t.Errorf("expected 200, got %d", rr.Code) }
}
