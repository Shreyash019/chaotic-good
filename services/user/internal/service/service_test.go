package service

import (
	"errors"
	"testing"
	"time"

	"github.com/Shreyash019/chaotic-good/services/user/internal/model"
)

type mockUserRepo struct{ profiles map[string]*model.UserProfile }

func newMockUserRepo() *mockUserRepo { return &mockUserRepo{profiles: make(map[string]*model.UserProfile)} }
func (m *mockUserRepo) GetByID(id string) (*model.UserProfile, error) {
	p, ok := m.profiles[id]; if !ok { return nil, errors.New("not found") }; return p, nil
}
func (m *mockUserRepo) Upsert(p *model.UserProfile) error {
	if _, ok := m.profiles[p.ID]; !ok { m.profiles[p.ID] = p }; return nil
}
func (m *mockUserRepo) Update(id string, req *model.UpdateProfileRequest) (*model.UserProfile, error) {
	p, ok := m.profiles[id]; if !ok { return nil, errors.New("not found") }
	if req.Name != "" { p.Name = req.Name }
	if req.Bio != "" { p.Bio = req.Bio }
	p.UpdatedAt = time.Now(); return p, nil
}
func (m *mockUserRepo) Delete(id string) error {
	if _, ok := m.profiles[id]; !ok { return errors.New("not found") }
	delete(m.profiles, id); return nil
}

func TestGetProfile_LazyCreate(t *testing.T) {
	repo := newMockUserRepo()
	p, err := NewUserService(repo).GetProfile("u1", "u@t.com")
	if err != nil { t.Fatalf("unexpected: %v", err) }
	if p.ID != "u1" { t.Errorf("expected u1, got %s", p.ID) }
}

func TestGetProfile_Existing(t *testing.T) {
	repo := newMockUserRepo()
	repo.profiles["u2"] = &model.UserProfile{ID: "u2", Name: "Alice"}
	p, _ := NewUserService(repo).GetProfile("u2", "")
	if p.Name != "Alice" { t.Errorf("expected Alice, got %s", p.Name) }
}

func TestUpdateProfile_OK(t *testing.T) {
	repo := newMockUserRepo()
	repo.profiles["u3"] = &model.UserProfile{ID: "u3"}
	p, err := NewUserService(repo).UpdateProfile("u3", &model.UpdateProfileRequest{Name: "Bob"})
	if err != nil { t.Fatalf("unexpected: %v", err) }
	if p.Name != "Bob" { t.Errorf("expected Bob, got %s", p.Name) }
}

func TestUpdateProfile_NotFound(t *testing.T) {
	if _, err := NewUserService(newMockUserRepo()).UpdateProfile("ghost", &model.UpdateProfileRequest{Name: "X"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestDeleteProfile_OK(t *testing.T) {
	repo := newMockUserRepo()
	repo.profiles["u4"] = &model.UserProfile{ID: "u4"}
	if err := NewUserService(repo).DeleteProfile("u4"); err != nil { t.Fatalf("unexpected: %v", err) }
	if _, ok := repo.profiles["u4"]; ok { t.Error("should be deleted") }
}

func TestDeleteProfile_NotFound(t *testing.T) {
	if err := NewUserService(newMockUserRepo()).DeleteProfile("ghost"); err == nil { t.Fatal("expected error") }
}
