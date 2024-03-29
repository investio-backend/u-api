package service

import (
	"crypto/ed25519"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"gitlab.com/investio/backend/user-api/v1/schema"
	"gopkg.in/square/go-jose.v2/jwt"
)

type AuthService interface {
	DecodeToken(rawJWT string) (parsedJWT *jwt.JSONWebToken, result *schema.TokenClaims, err error)
	IsExpired(payload *schema.TokenClaims) (exp bool, diff float64)
	ExtractHeader(r *http.Request) string
	ValidateAccessToken(r *http.Request) (accessJwt *schema.TokenClaims, errReason string)
}

type authService struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

func NewAuthService() AuthService {
	return &authService{}
}

// Parse & validate token
func (s *authService) DecodeToken(rawJWT string) (parsedJWT *jwt.JSONWebToken, result *schema.TokenClaims, err error) {
	// First attempt
	if s.PublicKey == nil {
		err = s.setKey()
		if err != nil {
			log.Println("Cannot read .key file: ", err)
			return
		}
	}
	parsedJWT, err = jwt.ParseSigned(rawJWT)
	if err != nil {
		log.Println("Failed to get claims JWT: ", err)
		return
	}
	result = &schema.TokenClaims{}
	err = parsedJWT.Claims(s.PublicKey, result)
	return
}

func (s *authService) setKey() (err error) {
	// Read seed
	seed, err := ioutil.ReadFile("./keys/token.key")
	if err != nil {
		return
	}
	var ok bool
	// Create the key from seed
	s.PrivateKey = ed25519.NewKeyFromSeed(seed)
	s.PublicKey, ok = s.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		err = errors.New("problem with casting public key to ed25519 public key")
	}
	return
}

func (s *authService) IsExpired(payload *schema.TokenClaims) (exp bool, diff float64) {
	now := time.Now()
	expired := payload.Expiry.Time()

	diff = expired.Sub(now).Seconds()
	if diff <= 0 {
		exp = true
	}
	return
}

func (s *authService) ExtractHeader(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	//normally Authorization the_token_xxx
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func (s *authService) ValidateAccessToken(r *http.Request) (accessJWT *schema.TokenClaims, errReason string) {
	var err error
	// Get access token
	accessToken := s.ExtractHeader(r)

	if accessToken == "" {
		errReason = "Token is empty"
		return
	}

	_, accessJWT, err = s.DecodeToken(accessToken)
	if err != nil {
		errReason = err.Error()
		return
	}

	if accessJWT.IsRefresh {
		errReason = "Token is invalid"
		return
	}

	isExp, _ := s.IsExpired(accessJWT)
	if isExp {
		errReason = "Token expired"

	}

	return

}
