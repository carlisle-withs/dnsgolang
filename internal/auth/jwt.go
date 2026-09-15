// Package auth 实现 JWT 签发/校验/刷新(HS256,payload 结构沿用原
// djangorestframework-jwt 约定:token_type/user_id/username/exp/iat/orig_iat)。
package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("token 无效")
	ErrExpired      = errors.New("token 已过期")
)

type Claims struct {
	TokenType string `json:"token_type"`
	UserID    uint64 `json:"user_id"`
	Username  string `json:"username"`
	OrigIat   int64  `json:"orig_iat"`
	jwt.RegisteredClaims
}

type Manager struct {
	secret     []byte
	ttl        time.Duration
	refreshTTL time.Duration
}

func NewManager(secret string, ttlHours, refreshDays int) *Manager {
	return &Manager{
		secret:     []byte(secret),
		ttl:        time.Duration(ttlHours) * time.Hour,
		refreshTTL: time.Duration(refreshDays) * 24 * time.Hour,
	}
}

func (m *Manager) Issue(userID uint64, username string) (string, error) {
	now := time.Now()
	claims := &Claims{
		TokenType: "access",
		UserID:    userID,
		Username:  username,
		OrigIat:   now.Unix(),
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
}

func (m *Manager) Parse(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, ErrInvalidToken
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// Refresh 校验旧 token(允许已过期,但须在 orig_iat 起 refreshTTL 窗口内)并换发新 token。
func (m *Manager) Refresh(tokenStr string) (string, error) {
	claims, err := m.Parse(tokenStr)
	if err != nil && !errors.Is(err, ErrInvalidToken) {
		return "", err
	}
	if claims == nil {
		return "", ErrInvalidToken
	}
	now := time.Now()
	if now.Unix()-claims.OrigIat > int64(m.refreshTTL.Seconds()) {
		return "", errors.New("token 刷新窗口已过期")
	}
	newClaims := &Claims{
		TokenType: "access",
		UserID:    claims.UserID,
		Username:  claims.Username,
		OrigIat:   claims.OrigIat,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims).SignedString(m.secret)
}
