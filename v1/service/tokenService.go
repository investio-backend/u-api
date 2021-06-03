package service

import (
	"crypto/ed25519"
	"io/ioutil"
	"log"
	"time"

	"github.com/twinj/uuid"
	"gitlab.com/investio/backend/user-api/v1/schema"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type TokenService interface {
	CreateTokens(userID uint) (tokens schema.Tokens, err error)
	IssueToken(userID uint, tokenType schema.TokenType) (JwtStr string, tokenClaims schema.TokenClaims, err error)
}

type tokenService struct {
	builder jwt.Builder
}

func NewTokenService() TokenService {
	return &tokenService{}
}

func (s *tokenService) CreateTokens(userID uint) (tokens schema.Tokens, err error) {
	accessJWT, accessClaims, err := s.IssueToken(userID, schema.AccessTokenType)
	if err != nil {
		return
	}
	refreshJWT, refreshClaims, err := s.IssueToken(userID, schema.RefreshTokenType)

	tokens = schema.Tokens{
		AccessToken:  accessJWT,
		AcsExpires:   accessClaims.Expiry.Time().Unix(),
		RefreshToken: refreshJWT,
		RefExpires:   refreshClaims.Expiry.Time().Unix(),
	}
	return
}

func (s *tokenService) IssueToken(userID uint, tokenType schema.TokenType) (JwtStr string, tokenClaims schema.TokenClaims, err error) {
	ACS_TTL := time.Minute * 30
	REF_TTL := time.Hour * 24 * 7

	if s.builder == nil {
		var (
			privateKey ed25519.PrivateKey
			seed       []byte
			rsaSigner  jose.Signer
		)

		// Read seed
		seed, err = ioutil.ReadFile("./keys/token.key")
		if err != nil {
			// Create a new key
			privateKey, _, err = s.genKeyAndWriteSeed()
			if err != nil {
				panic(err)
			}
		} else {
			// Create the key from seed
			privateKey = ed25519.NewKeyFromSeed(seed)
		}

		// create Square.jose signing key
		key := jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey}
		// create a Square.jose RSA signer, used to sign the JWT
		var signerOpts = jose.SignerOptions{}
		signerOpts.WithType("JWT")
		rsaSigner, err = jose.NewSigner(key, &signerOpts)
		if err != nil {
			log.Println("failed to create signer: ", err)
			return
		}
		// create an instance of Builder that uses the rsa signer
		s.builder = jwt.Signed(rsaSigner)
	}

	if tokenType == schema.AccessTokenType {
		// create a Claim of the Access Token
		tokenClaims = schema.TokenClaims{
			Claims: &jwt.Claims{
				Issuer:   "investio-api:user",
				Subject:  "acs:you@inv.me",
				ID:       uuid.NewV4().String(),
				Audience: jwt.Audience{"investio.dewkul.me", "investio.netlify.app"},
				IssuedAt: jwt.NewNumericDate(time.Now()),
				Expiry:   jwt.NewNumericDate(time.Now().Add(ACS_TTL)),
			},
			UserID:       userID,
			IsAuthorized: true,
			IsRefresh:    false,
		}
	} else if tokenType == schema.RefreshTokenType {
		// create a Claim of the Access Token
		tokenClaims = schema.TokenClaims{
			Claims: &jwt.Claims{
				Issuer:   "investio-api:user",
				Subject:  "ref:you@inv.me",
				ID:       uuid.NewV4().String(),
				Audience: jwt.Audience{"investio.dewkul.me", "investio.netlify.app"},
				IssuedAt: jwt.NewNumericDate(time.Now()),
				Expiry:   jwt.NewNumericDate(time.Now().Add(REF_TTL)),
			},
			UserID:       userID,
			IsAuthorized: true,
			IsRefresh:    true,
		}
	}

	// add claims to the Builder
	s.builder = s.builder.Claims(tokenClaims)

	// validate all ok, sign with the Ed25519 key, and return a compact JWT
	JwtStr, err = s.builder.CompactSerialize()
	if err != nil {
		log.Println("failed to create JWT: ", err)
	}
	return
}

func (s *tokenService) genKeyAndWriteSeed() (privKey ed25519.PrivateKey, pubKey ed25519.PublicKey, err error) {
	pubKey, privKey, err = ed25519.GenerateKey(nil)
	if err != nil {
		return
	}
	seed := privKey.Seed()
	err = ioutil.WriteFile("./keys/token.key", seed, 0600)
	return
}
