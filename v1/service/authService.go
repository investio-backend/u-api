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
	// if err != nil {
	// 	log.Println("Failed to get claims JWT:%+v", err)
	// }
	return
}

func (s *authService) setKey() (err error) {
	// Read seed
	seed, err := ioutil.ReadFile("token.key")
	if err != nil {
		return
	}
	var ok bool
	// Create the key from seed
	s.PrivateKey = ed25519.NewKeyFromSeed(seed)
	s.PublicKey, ok = s.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		// fmt.Println("problem casting public key to ed25519 public key")
		err = errors.New("problem casting public key to ed25519 public key")
		// panic(err.Error())
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
