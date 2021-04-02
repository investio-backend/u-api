package schema

import "gopkg.in/square/go-jose.v2/jwt"

type AuthDetail struct {
	// UUID   string
	ID     string // JTI
	UserID string
}

type TokenClaims struct {
	UserID       string `json:"user_id"`
	IsAuthorized bool   `json:"is_authorized"`
	IsRefresh    bool   `json:"is_refresh"`
	// AccessUUID string `json:"access-UUID"`
	*jwt.Claims
}

// type RefreshTokenClaims struct {
// 	UserID     string `json:"user_id"`
// 	Authorized bool   `json:"is_authorized"`
// 	// RefreshUUID string `json:"refresh-UUID"`
// 	*jwt.Claims
// }
