package service

import (
	"errors"
	"testing"

	"github.com/shreyashkumar/funny-pipe/services/auth/internal/model"
)

type mockAuthRepo struct{ users map[string]*model.User }

func newMockRepo() *mockAuthRepo { return &mockAuthRepo{users: make(map[string]*model.User)} }
func (m *mockAuthRepo) CreateUser(u *model.User) error {
	if _, ok := m.users[u.Email]; ok { return errors.New("user already exists") }
	m.users[u.Email] = u; return nil
}
func (m *mockAuthRepo) GetUserByEmail(email string) (*model.User, error) {
	u, ok := m.users[email]; if !ok { return nil, errors.New("user not found") }; return u, nil
}
func (m *mockAuthRepo) GetUserByID(id string) (*model.User, error) {
	for _, u := range m.users { if u.ID == id { return u, nil } }
	return nil, errors.New("user not found")
}

func TestRegister_Success(t *testing.T) {
	svc := NewAuthService(newMockRepo(), "secret")
	if err := svc.Register(&model.RegisterRequest{Email: "a@b.com", Password: "pass"}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	svc := NewAuthService(newMockRepo(), "secret")
	_ = svc.Register(&model.RegisterRequest{Email: "a@b.com", Password: "pass"})
	if err := svc.Register(&model.RegisterRequest{Email: "a@b.com", Password: "x"}); err == nil {
		t.Fatal("expected duplicate-email error")
	}
}

func TestLogin_Success(t *testing.T) {
	svc := NewAuthService(newMockRepo(), "secret")
	_ = svc.Register(&model.RegisterRequest{Email: "l@b.com", Password: "pass"})
	resp, refresh, err := svc.Login(&model.LoginRequest{Email: "l@b.com", Password: "pass"})
	if err != nil { t.Fatalf("unexpected: %v", err) }
	if resp.AccessToken == "" { t.Fatal("empty access token") }
	if refresh == "" { t.Fatal("empty refresh token") }
}

func TestLogin_WrongPassword(t *testing.T) {
	svc := NewAuthService(newMockRepo(), "secret")
	_ = svc.Register(&model.RegisterRequest{Email: "p@b.com", Password: "right"})
	if _, _, err := svc.Login(&model.LoginRequest{Email: "p@b.com", Password: "wrong"}); err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestLogin_UnknownEmail(t *testing.T) {
	svc := NewAuthService(newMockRepo(), "secret")
	if _, _, err := svc.Login(&model.LoginRequest{Email: "x@b.com", Password: "p"}); err == nil {
		t.Fatal("expected error for unknown email")
	}
}

func TestValidateToken_RoundTrip(t *testing.T) {
	svc := NewAuthService(newMockRepo(), "round-secret")
	_ = svc.Register(&model.RegisterRequest{Email: "rt@b.com", Password: "pass"})
	resp, _, err := svc.Login(&model.LoginRequest{Email: "rt@b.com", Password: "pass"})
	if err != nil { t.Fatalf("login: %v", err) }
	claims, err := svc.ValidateToken(resp.AccessToken)
	if err != nil { t.Fatalf("validate: %v", err) }
	if claims.Email != "rt@b.com" { t.Errorf("got %s", claims.Email) }
}

func TestValidateToken_Invalid(t *testing.T) {
	svc := NewAuthService(newMockRepo(), "secret")
	if _, err := svc.ValidateToken("garbage.token.here"); err == nil {
		t.Fatal("expected error for invalid token")
	}
}
