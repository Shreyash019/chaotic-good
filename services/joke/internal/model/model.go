package model

import "time"

type Joke struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Content   string    `json:"content"`
	Category  string    `json:"category"`
	CreatedAt time.Time `json:"created_at"`
}

type CreateJokeInput struct {
	Content  string `json:"content"`
	Category string `json:"category"`
}
