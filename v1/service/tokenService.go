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
	CreateTokens(userID string) (tokens schema.Tokens, err error)
	IssueToken(userID string, tokenType schema.TokenType) (JwtStr string, tokenClaims schema.TokenClaims, err error)
}

type tokenService struct {
	// privateKey ed25519.PrivateKey
	builder jwt.Builder
}

func NewTokenService() TokenService {
	return &tokenService{}
}

// func exportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
// 	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
// 	privkey_pem := pem.EncodeToMemory(
// 		&pem.Block{
// 			Type:  "RSA PRIVATE KEY",
// 			Bytes: privkey_bytes,
// 		},
// 	)
// 	return string(privkey_pem)
// }

// func parseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
// 	block, _ := pem.Decode([]byte(privPEM))
// 	if block == nil {
// 		return nil, errors.New("failed to parse PEM block containing the key")
// 	}

// 	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return priv, nil
// }

// func (s *tokenService) genNewRsaToken() (rsaPrivKey *rsa.PrivateKey, err error) {
// 	// Create the RSA key pair in the code
// 	rsaPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
// 	if err != nil {
// 		log.Println("generating random key: %v", err)
// 		return
// 	}

// 	privKeyStr := exportRsaPrivateKeyAsPemStr(rsaPrivKey)
// 	// Write file
// 	err = ioutil.WriteFile("id_rsa.pem", []byte(privKeyStr), 0600)
// 	return
// }

func (s *tokenService) CreateTokens(userID string) (tokens schema.Tokens, err error) {
	// var privateKey ed25519.PrivateKey
	// // publicKey  ed25519.PublicKey
	// // ok         bool

	// ACS_TTL := time.Minute * 2
	// REF_TTL := time.Hour * 1

	// // Read seed
	// seed, err := ioutil.ReadFile("token.key")
	// if err != nil {
	// 	// Create a new key
	// 	privateKey, _, err = s.genKeyAndWriteSeed()
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// } else {
	// 	// Create the key from seed
	// 	privateKey = ed25519.NewKeyFromSeed(seed)
	// 	// publicKey, ok = privateKey.Public().(ed25519.PublicKey)
	// 	// if !ok {
	// 	// 	// fmt.Println("problem casting public key to ed25519 public key")
	// 	// 	err = errors.New("problem casting public key to ed25519 public key")
	// 	// 	panic(err.Error())
	// 	// }
	// }

	// // create Square.jose signing key
	// key := jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey}
	// // create a Square.jose RSA signer, used to sign the JWT
	// var signerOpts = jose.SignerOptions{}
	// signerOpts.WithType("JWT")
	// rsaSigner, err := jose.NewSigner(key, &signerOpts)
	// if err != nil {
	// 	log.Println("failed to create signer: ", err)
	// 	return
	// }

	// // create an instance of Builder that uses the rsa signer
	// s.builder = jwt.Signed(rsaSigner)

	// // create a Claim of the Access Token
	// accessClaims := schema.TokenClaims{
	// 	Claims: &jwt.Claims{
	// 		Issuer:   "investio-api:user",
	// 		Subject:  "acs:you@inv.me",
	// 		ID:       uuid.NewV4().String(),
	// 		Audience: jwt.Audience{"investio.dewkul.me", "investio.netlify.app"},
	// 		IssuedAt: jwt.NewNumericDate(time.Now()),
	// 		Expiry:   jwt.NewNumericDate(time.Now().Add(ACS_TTL)),
	// 	},
	// 	UserID:       userID,
	// 	IsAuthorized: true,
	// 	IsRefresh:    false,
	// }
	// // add claims to the Builder
	// s.builder = s.builder.Claims(accessClaims)

	// // validate all ok, sign with the RSA key, and return a compact JWT
	// accessJWT, err := s.builder.CompactSerialize()
	// if err != nil {
	// 	log.Println("failed to create JWT: ", err)
	// }

	// // fmt.Println(accessJWT)

	// // create a Claim of the Access Token
	// refreshClaims := schema.TokenClaims{
	// 	Claims: &jwt.Claims{
	// 		Issuer:   "investio-api:user",
	// 		Subject:  "ref:you@inv.me",
	// 		ID:       uuid.NewV4().String(),
	// 		Audience: jwt.Audience{"investio.dewkul.me", "investio.netlify.app"},
	// 		IssuedAt: jwt.NewNumericDate(time.Now()),
	// 		Expiry:   jwt.NewNumericDate(time.Now().Add(REF_TTL)),
	// 	},
	// 	UserID:       userID,
	// 	IsAuthorized: true,
	// 	IsRefresh:    true,
	// }
	// // add claims to the Builder
	// s.builder = s.builder.Claims(refreshClaims)

	// // validate all ok, sign with the RSA key, and return a compact JWT
	// refreshJWT, err := s.builder.CompactSerialize()
	// if err != nil {
	// 	log.Println("failed to create JWT: ", err)
	// }

	// // fmt.Println(refreshJWT)

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

func (s *tokenService) IssueToken(userID string, tokenType schema.TokenType) (JwtStr string, tokenClaims schema.TokenClaims, err error) {

	ACS_TTL := time.Minute * 2
	REF_TTL := time.Hour * 1

	if s.builder == nil {
		var (
			privateKey ed25519.PrivateKey
			seed       []byte
			rsaSigner  jose.Signer
		)

		// Read seed
		seed, err = ioutil.ReadFile("token.key")
		if err != nil {
			// Create a new key
			privateKey, _, err = s.genKeyAndWriteSeed()
			if err != nil {
				panic(err)
			}
		} else {
			// Create the key from seed
			privateKey = ed25519.NewKeyFromSeed(seed)
			// publicKey, ok = privateKey.Public().(ed25519.PublicKey)
			// if !ok {
			// 	// fmt.Println("problem casting public key to ed25519 public key")
			// 	err = errors.New("problem casting public key to ed25519 public key")
			// 	panic(err.Error())
			// }
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
		// // add claims to the Builder
		// s.builder = s.builder.Claims(tokenClaims)
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
		// // add claims to the Builder
		// s.builder = s.builder.Claims(refreshClaims)
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
	err = ioutil.WriteFile("token.key", seed, 0600)
	return
}

// func (s *tokenService) CreateOldTokens(userID string) {
// 	// Create the RSA key pair in the code
// 	rsaPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)

// 	// create Square.jose signing key
// 	key := jose.SigningKey{Algorithm: jose.RS256, Key: rsaPrivKey}

// 	// create a Square.jose RSA signer, used to sign the JWT
// 	var signerOpts = jose.SignerOptions{}
// 	signerOpts.WithType("JWT")
// 	rsaSigner, err := jose.NewSigner(key, &signerOpts)
// 	if err != nil {
// 		log.Println("failed to create signer:%+v", err)
// 	}

// 	// create an instance of Builder that uses the rsa signer
// 	builder := jwt.Signed(rsaSigner)

// 	// create an instance of the CustomClaim
// 	customClaims := TokenClaims{
// 		Claims: &jwt.Claims{
// 			Issuer:   "issuer1",
// 			Subject:  "subject1",
// 			ID:       uuid.NewV4().String(),
// 			Audience: jwt.Audience{"aud1", "aud2"},
// 			IssuedAt: jwt.NewNumericDate(time.Now()),
// 			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Minute * 1)),
// 		},
// 		UserID:     userID,
// 		Authorized: true,
// 	}
// 	// add claims to the Builder
// 	builder = builder.Claims(customClaims)

// 	// validate all ok, sign with the RSA key, and return a compact JWT
// 	rawJWT, err := builder.CompactSerialize()
// 	if err != nil {
// 		log.Println("failed to create JWT:%+v", err)
// 	}
// 	fmt.Println(rawJWT)

// }

// func readKey() (privateKey *rsa.PrivateKey, err error) {
// rsaPrivateKeyLocation := "./id_rsa"
// priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
// if err != nil {
// 	fmt.Println("No RSA private key found")
// 	return nil, err
// }

// return
// }
