package repository

import (
	"testing"

	"github.com/shreyashkumar/funny-pipe/services/joke/internal/model"
)

func newRepo() IJokeRepository { return NewInMemoryJokeRepository() }

func TestCreate_GetByID(t *testing.T) {
	repo := newRepo()
	j, err := repo.Create("u1", &model.CreateJokeInput{Content: "Why Go?", Category: "tech"})
	if err != nil { t.Fatalf("unexpected: %v", err) }
	got, err := repo.GetByID(j.ID)
	if err != nil { t.Fatalf("GetByID: %v", err) }
	if got.Content != "Why Go?" { t.Errorf("wrong content: %s", got.Content) }
}

func TestGetByID_NotFound(t *testing.T) {
	if _, err := newRepo().GetByID("missing"); err == nil { t.Fatal("expected error") }
}

func TestList_All(t *testing.T) {
	repo := newRepo()
	repo.Create("u1", &model.CreateJokeInput{Content: "A", Category: "tech"})
	repo.Create("u1", &model.CreateJokeInput{Content: "B", Category: "dad"})
	jokes, _ := repo.List("", 10)
	if len(jokes) != 2 { t.Errorf("expected 2, got %d", len(jokes)) }
}

func TestList_Category(t *testing.T) {
	repo := newRepo()
	repo.Create("u1", &model.CreateJokeInput{Content: "A", Category: "tech"})
	repo.Create("u1", &model.CreateJokeInput{Content: "B", Category: "dad"})
	jokes, _ := repo.List("tech", 10)
	if len(jokes) != 1 || jokes[0].Category != "tech" { t.Errorf("unexpected: %v", jokes) }
}

func TestList_Limit(t *testing.T) {
	repo := newRepo()
	for i := 0; i < 5; i++ { repo.Create("u1", &model.CreateJokeInput{Content: "x", Category: "x"}) }
	jokes, _ := repo.List("", 3)
	if len(jokes) != 3 { t.Errorf("expected 3, got %d", len(jokes)) }
}

func TestRandom_OK(t *testing.T) {
	repo := newRepo()
	repo.Create("u1", &model.CreateJokeInput{Content: "A", Category: "tech"})
	j, err := repo.Random("tech")
	if err != nil { t.Fatalf("unexpected: %v", err) }
	if j == nil { t.Fatal("expected joke, got nil") }
}

func TestRandom_EmptyPool(t *testing.T) {
	if _, err := newRepo().Random("empty"); err == nil { t.Fatal("expected error") }
}

func TestDelete_OK(t *testing.T) {
	repo := newRepo()
	j, _ := repo.Create("u1", &model.CreateJokeInput{Content: "bye", Category: "x"})
	if err := repo.Delete(j.ID, "u1"); err != nil { t.Fatalf("unexpected: %v", err) }
	if _, err := repo.GetByID(j.ID); err == nil { t.Fatal("should be deleted") }
}

func TestDelete_WrongOwner(t *testing.T) {
	repo := newRepo()
	j, _ := repo.Create("u1", &model.CreateJokeInput{Content: "x", Category: "x"})
	if err := repo.Delete(j.ID, "u2"); err == nil { t.Fatal("expected forbidden error") }
}

func TestDelete_NotFound(t *testing.T) {
	if err := newRepo().Delete("ghost", "u1"); err == nil { t.Fatal("expected not-found error") }
}
