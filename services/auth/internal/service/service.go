package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/Shreyash019/chaotic-good/services/auth/internal/model"
	"github.com/Shreyash019/chaotic-good/services/auth/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// IAuthService defines the interface for auth service
type IAuthService interface {
	Register(req *model.RegisterRequest) error
	Login(req *model.LoginRequest) (*model.AuthResponse, string, error) // returns (response, refreshToken, error)
	ValidateToken(tokenString string) (*model.Claims, error)
}

type AuthService struct {
	repo      repository.IAuthRepository
	jwtSecret []byte
}

func NewAuthService(repo repository.IAuthRepository, jwtSecret string) IAuthService {
	return &AuthService{
		repo:      repo,
		jwtSecret: []byte(jwtSecret),
	}
}

func (s *AuthService) Register(req *model.RegisterRequest) error {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user := &model.User{
		ID:        generateID(),
		Email:     req.Email,
		Password:  string(hashedPassword),
		CreatedAt: time.Now(),
	}

	return s.repo.CreateUser(user)
}

func (s *AuthService) Login(req *model.LoginRequest) (*model.AuthResponse, string, error) {
	// Get user by email
	user, err := s.repo.GetUserByEmail(req.Email)
	if err != nil {
		return nil, "", errors.New("invalid credentials")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, "", errors.New("invalid credentials")
	}

	// Generate access token (15 mins)
	accessToken, err := s.generateToken(user, 15*time.Minute)
	if err != nil {
		return nil, "", err
	}

	// Generate refresh token (7 days) — returned separately, set as HttpOnly cookie by handler
	refreshToken, err := s.generateToken(user, 7*24*time.Hour)
	if err != nil {
		return nil, "", err
	}

	return &model.AuthResponse{
		AccessToken: accessToken,
		ExpiresIn:   time.Now().Add(15 * time.Minute).Unix(),
	}, refreshToken, nil
}

func (s *AuthService) ValidateToken(tokenString string) (*model.Claims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	jwtClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	return &model.Claims{
		UserID: jwtClaims["user_id"].(string),
		Email:  jwtClaims["email"].(string),
		Exp:    int64(jwtClaims["exp"].(float64)),
	}, nil
}

// helpers
func (s *AuthService) generateToken(user *model.User, duration time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(duration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
