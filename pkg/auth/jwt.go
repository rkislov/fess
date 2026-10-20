package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
)

type Service struct {
	secret          []byte
	accessTTL       time.Duration
	refreshTTL      time.Duration
	issuer          string
	authDisabled    bool
}

func NewService(secret string, accessTTL, refreshTTL time.Duration, authDisabled bool) (*Service, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" && !authDisabled {
		return nil, fmt.Errorf("FENCE_JWT_SECRET is required when auth is enabled")
	}
	if accessTTL <= 0 {
		accessTTL = 15 * time.Minute
	}
	if refreshTTL <= 0 {
		refreshTTL = 7 * 24 * time.Hour
	}
	return &Service{
		secret:       []byte(secret),
		accessTTL:    accessTTL,
		refreshTTL:   refreshTTL,
		issuer:       "fence",
		authDisabled: authDisabled,
	}, nil
}

func (s *Service) AuthDisabled() bool {
	return s.authDisabled
}

func (s *Service) AccessTTL() time.Duration {
	return s.accessTTL
}

func (s *Service) RefreshTTL() time.Duration {
	return s.refreshTTL
}

type accessClaims struct {
	jwt.RegisteredClaims
	Username string `json:"username"`
	Role     string `json:"role"`
}

func (s *Service) IssueAccessToken(u User) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(s.accessTTL)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID,
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		Username: u.Username,
		Role:     u.Role,
	})
	signed, err := tok.SignedString(s.secret)
	return signed, exp, err
}

func (s *Service) ParseAccessToken(token string) (Claims, error) {
	if s.authDisabled {
		return Claims{UserID: "dev", Username: "dev", Role: RoleAdmin}, nil
	}
	parsed, err := jwt.ParseWithClaims(strings.TrimSpace(token), &accessClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, ErrInvalidToken
		}
		return s.secret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return Claims{}, ErrExpiredToken
		}
		return Claims{}, ErrInvalidToken
	}
	claims, ok := parsed.Claims.(*accessClaims)
	if !ok || !parsed.Valid {
		return Claims{}, ErrInvalidToken
	}
	return Claims{
		UserID:   claims.Subject,
		Username: claims.Username,
		Role:     claims.Role,
	}, nil
}

func NewRefreshToken() (raw string, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return raw, hash, nil
}

func HashRefreshToken(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}
