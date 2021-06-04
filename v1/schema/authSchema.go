package schema

import "gopkg.in/square/go-jose.v2/jwt"

type AuthDetail struct {
	ID     string // JTI
	UserID uint
}

type TokenClaims struct {
	UserID       uint `json:"user_id"`
	IsAuthorized bool `json:"is_authorized"`
	IsRefresh    bool `json:"is_refresh"`
	*jwt.Claims
}
