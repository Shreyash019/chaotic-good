package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Logger middleware logs each request
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf(
			"[%s] %s %s %s",
			r.Method,
			r.RequestURI,
			r.RemoteAddr,
			time.Since(start),
		)
	})
}

// CORS middleware handles cross-origin requests
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Chain chains multiple middlewares together
func Chain(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret        []byte
	SkippedRoutes []string // routes that don't need auth
}

// Auth middleware validates JWT token
func Auth(config JWTConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if route should skip auth
			for _, route := range config.SkippedRoutes {
				if strings.HasPrefix(r.URL.Path, route) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Extract token from header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			// Remove "Bearer " prefix
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				http.Error(w, "Invalid authorization format. Use: Bearer <token>", http.StatusUnauthorized)
				return
			}

			// Validate token
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, http.ErrNoCookie
				}
				return config.Secret, nil
			})

			if err != nil || !token.Valid {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			// Extract claims and forward to next handler
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, "Invalid token claims", http.StatusUnauthorized)
				return
			}

			// Inject user info into request headers for downstream services
			r.Header.Set("X-User-ID", claims["user_id"].(string))
			r.Header.Set("X-User-Email", claims["email"].(string))

			next.ServeHTTP(w, r)
		})
	}
}

// ---- Rate Limiter ----

type client struct {
	count    int
	lastSeen time.Time
}

type RateLimiterConfig struct {
	RequestsPerMinute int
}

var (
	clients = make(map[string]*client)
	mu      sync.Mutex
)

// RateLimiter middleware limits requests per IP
func RateLimiter(config RateLimiterConfig) func(http.Handler) http.Handler {
	// Cleanup old clients every minute
	go func() {
		for {
			time.Sleep(time.Minute)
			mu.Lock()
			for ip, c := range clients {
				if time.Since(c.lastSeen) > time.Minute {
					delete(clients, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr

			mu.Lock()
			c, exists := clients[ip]
			if !exists || time.Since(c.lastSeen) > time.Minute {
				clients[ip] = &client{count: 1, lastSeen: time.Now()}
				mu.Unlock()
				next.ServeHTTP(w, r)
				return
			}

			if c.count >= config.RequestsPerMinute {
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Too many requests. Please try again later.",
				})
				return
			}

			c.count++
			c.lastSeen = time.Now()
			mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}
