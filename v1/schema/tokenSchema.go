package schema

type TokenType int

const (
	unknown TokenType = iota
	AccessTokenType
	RefreshTokenType
	sentinel
)

type TokenDetail struct {
	// AccessToken  string
	// RefreshToken string
	AccessUuid  string
	RefreshUuid string
	AtExpires   int64 // Access Token Exp
	RtExpires   int64 // Refresh Token Exp
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AcsExpires   int64  // Access Token Exp
	RefExpires   int64  // Refresh Token Exp
}
