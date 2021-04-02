package controller

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gitlab.com/investio/backend/user-api/v1/schema"
	"gitlab.com/investio/backend/user-api/v1/service"
)

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

//A sample use
var user = User{
	ID:       "46",
	Username: "LnwTarn",
	Password: "CrazyTarnny",
}

type TokenController interface {
	Login(ctx *gin.Context)
	LogOut(ctx *gin.Context)
	Refresh(ctx *gin.Context)
}

type tokenController struct {
	tokenService service.TokenService
	authService  service.AuthService
	redisService service.RedisService
}

func NewTokenController(tokenService service.TokenService, authService service.AuthService, redisService service.RedisService) TokenController {
	return &tokenController{
		tokenService: tokenService,
		authService:  authService,
		redisService: redisService,
	}
}

func (c *tokenController) Login(ctx *gin.Context) {
	var u User

	if err := ctx.ShouldBindJSON(&u); err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, "Invalid JSON provided")
		return
	}
	//compare the user from the request, with the one we defined:
	if user.Username != u.Username || user.Password != u.Password {
		ctx.JSON(http.StatusUnauthorized, "Invalid login credentials")
		return
	}

	tokens, err := c.tokenService.CreateTokens(user.ID)
	if err != nil {
		log.Fatalln("Failed create token: ", err.Error())
		ctx.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	// if _, acsDiffExp := c.authService.IsExpired()

	now := time.Now().Unix()
	// TODO: Rm 192.168.50.233
	ctx.SetCookie("accessToken", tokens.AccessToken, int(tokens.AcsExpires-now), "/user", "192.168.50.233", false, true)
	ctx.SetCookie("refreshToken", tokens.RefreshToken, int(tokens.RefExpires-now), "/user", "192.168.50.233", false, true)
	ctx.SetCookie("accessToken", tokens.AccessToken, int(tokens.AcsExpires-now), "/user", "investio.api.dewkul.me", false, true)
	ctx.SetCookie("refreshToken", tokens.RefreshToken, int(tokens.RefExpires-now), "/user", "investio.api.dewkul.me", false, true)

	ctx.JSON(http.StatusOK, "hello") // TODO: Return user info
}

func (c *tokenController) LogOut(ctx *gin.Context) {
	// Get access token
	accessStr, err := ctx.Cookie("accessToken")
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	_, accessJWT, err := c.authService.DecodeToken(accessStr)
	if err != nil {
		ctx.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	isExp, _ := c.authService.IsExpired(accessJWT)
	if isExp {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Remove access token from client
	ctx.SetCookie("accessToken", "bye", -1, "/user", "192.168.50.233", false, true)
	ctx.SetCookie("accessToken", "bye", -1, "/user", "investio.api.dewkul.me", false, true)

	// TODO: Check blocked access token

	// Get Refresh Token
	refreshStr, err := ctx.Cookie("refreshToken")
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	_, refreshJWT, err := c.authService.DecodeToken(refreshStr)
	if err != nil {
		ctx.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	// Remove access token from client
	ctx.SetCookie("refreshToken", "bye", -1, "/user", "192.168.50.233", false, true)
	ctx.SetCookie("refreshToken", "bye", -1, "/user", "investio.api.dewkul.me", false, true)

	// Add tokens to blocklist
	tokenDetail := &schema.TokenDetail{
		AccessUuid:  accessJWT.Claims.ID,
		RefreshUuid: refreshJWT.Claims.ID,
		AtExpires:   int64(*accessJWT.Claims.Expiry),
		RtExpires:   int64(*refreshJWT.Claims.Expiry),
	}

	if accessJWT.UserID != refreshJWT.UserID {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		log.Println("Invalid access != refresh")
		return
	}

	if err := c.redisService.BlockTokens(accessJWT.UserID, tokenDetail); err != nil {
		ctx.AbortWithError(http.StatusBadGateway, err)
		log.Println("Redis: ", err.Error())
		return
	}

	ctx.JSON(http.StatusOK, "Logged out")
}

func (c *tokenController) Refresh(ctx *gin.Context) {
	REF_TOKEN_MIN_TTL := time.Minute * 10

	// Get refresh token
	refreshStr, err := ctx.Cookie("refreshToken")
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	_, refreshJWT, err := c.authService.DecodeToken(refreshStr)
	if err != nil {
		ctx.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	isExp, timeDiff := c.authService.IsExpired(refreshJWT)
	if isExp {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// TODO: Check blocked refresh token
	if timeDiff < REF_TOKEN_MIN_TTL.Seconds() {
		// Issue new refresh token
		jwtStr, jwtClaim, err := c.tokenService.IssueToken(refreshJWT.UserID, schema.RefreshTokenType)
		if err != nil {
			ctx.AbortWithError(http.StatusInternalServerError, err)
		}
		now := time.Now().Unix()

		// TODO: Remove 192.168.50.233
		ctx.SetCookie("refreshToken", jwtStr, int(jwtClaim.Expiry.Time().Unix()-now), "/user", "192.168.50.233", false, true)
		ctx.SetCookie("refreshToken", jwtStr, int(jwtClaim.Expiry.Time().Unix()-now), "/user", "investio.api.dewkul.me", false, true)
	}

	// Issue new access token
	jwtStr, jwtClaim, err := c.tokenService.IssueToken(refreshJWT.UserID, schema.AccessTokenType)
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err)
	}
	now := time.Now().Unix()

	// TODO: Remove 192.168.50.233
	ctx.SetCookie("accessToken", jwtStr, int(jwtClaim.Expiry.Time().Unix()-now), "/user", "192.168.50.233", false, true)
	ctx.SetCookie("accessToken", jwtStr, int(jwtClaim.Expiry.Time().Unix()-now), "/user", "investio.api.dewkul.me", false, true)
}
