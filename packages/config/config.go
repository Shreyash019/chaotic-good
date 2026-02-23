// Package config provides a simple .env file loader and typed config structs.
// Uses only the Go standard library — no external dependencies.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Load reads a .env file and sets each key=value pair as an environment variable.
// Existing env vars (already set in the shell) are NOT overwritten.
// Call Load() once at the start of main().
func Load(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		// .env is optional — warn but don't fail
		fmt.Printf("[config] warning: %v (using existing env vars)\n", err)
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// skip blank lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Don't overwrite vars already set in the shell environment
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}

	return scanner.Err()
}

// ─── Typed helpers ───────────────────────────────────────────

func GetString(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func GetInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

// ─── Typed config structs ────────────────────────────────────

type AuthConfig struct {
	Port             string
	JWTSecret        string
	AccessTTLMinutes int
	RefreshTTLDays   int
}

type GatewayConfig struct {
	Port               string
	RateLimitPerMinute int
	AuthServiceURL     string
	UserServiceURL     string
	JokeServiceURL     string
	JWTSecret          string
}

func LoadAuthConfig() AuthConfig {
	return AuthConfig{
		Port:             GetString("AUTH_PORT", "8081"),
		JWTSecret:        GetString("JWT_SECRET", "dev-secret-key"),
		AccessTTLMinutes: GetInt("JWT_ACCESS_TTL_MINUTES", 15),
		RefreshTTLDays:   GetInt("JWT_REFRESH_TTL_DAYS", 7),
	}
}

type UserConfig struct {
	Port string
}

func LoadUserConfig() UserConfig {
	return UserConfig{
		Port: GetString("USER_PORT", "8082"),
	}
}

// DBConfig holds the PostgreSQL connection string.
// If DatabaseURL is empty the services fall back to their in-memory stores.
type DBConfig struct {
	DatabaseURL string
}

func LoadDBConfig() DBConfig {
	return DBConfig{
		DatabaseURL: GetString("DATABASE_URL", ""),
	}
}

type JokeConfig struct {
	Port string
}

func LoadJokeConfig() JokeConfig {
	return JokeConfig{
		Port: GetString("JOKE_PORT", "8083"),
	}
}

func LoadGatewayConfig() GatewayConfig {
	return GatewayConfig{
		Port:               GetString("GATEWAY_PORT", "8080"),
		RateLimitPerMinute: GetInt("RATE_LIMIT_PER_MINUTE", 60),
		AuthServiceURL:     GetString("AUTH_SERVICE_URL", "http://localhost:8081"),
		UserServiceURL:     GetString("USER_SERVICE_URL", "http://localhost:8082"),
		JokeServiceURL:     GetString("JOKE_SERVICE_URL", "http://localhost:8083"),
		JWTSecret:          GetString("JWT_SECRET", "dev-secret-key"),
	}
}
