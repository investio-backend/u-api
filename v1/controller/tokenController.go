package controller

import (
	"fmt"
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
	domains      []string
}

func NewTokenController(tokenService service.TokenService, authService service.AuthService, redisService service.RedisService) TokenController {
	return &tokenController{
		tokenService: tokenService,
		authService:  authService,
		redisService: redisService,
		// TODO: Remove 192.168.50.233
		domains: []string{"dewkul.me", "192.168.50.233"},
	}
}

func (c *tokenController) Login(ctx *gin.Context) {
	var u User

	if err := ctx.ShouldBindJSON(&u); err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, "Invalid data provided")
		return
	}
	//compare the user from the request, with the one we defined:
	if user.Username != u.Username || user.Password != u.Password {
		ctx.JSON(http.StatusForbidden, "Invalid login credentials")
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
	for _, domain := range c.domains {
		ctx.SetCookie("acTk", tokens.AccessToken, int(tokens.AcsExpires-now), "/", domain, false, false)
		ctx.SetCookie("rfTk", tokens.RefreshToken, int(tokens.RefExpires-now), "/user", domain, false, true)
	}

	// ctx.JSON(http.StatusOK, "hello") // TODO: Return user info
	ctx.JSON(http.StatusOK, gin.H{
		"access":   tokens.AccessToken,
		"ref":      tokens.RefreshToken,
		"uid":      3,
		"username": "LnwTarn",
	})
}

func (c *tokenController) LogOut(ctx *gin.Context) {
	// Get access token
	accessStr, err := ctx.Cookie("acTk")
	if err != nil {
		fmt.Println(err.Error())
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// fmt.Println("Logout - access = ", accessStr)

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
	for _, domain := range c.domains {
		ctx.SetCookie("acTk", "bye", -1, "/", domain, false, true)
	}

	// TODO: Check blocked access token

	// Get Refresh Token
	refreshStr, err := ctx.Cookie("rfTk")
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	_, refreshJWT, err := c.authService.DecodeToken(refreshStr)
	if err != nil {
		ctx.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	// Remove refresh token from client
	for _, domain := range c.domains {
		ctx.SetCookie("rfTk", "bye", -1, "/user", domain, false, true)
	}

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
	refreshStr, err := ctx.Cookie("rfTk")
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	_, refreshJWT, err := c.authService.DecodeToken(refreshStr)
	if err != nil {
		ctx.AbortWithError(http.StatusForbidden, err)
		return
	}

	isExp, timeDiff := c.authService.IsExpired(refreshJWT)
	if isExp {
		ctx.AbortWithStatusJSON(http.StatusForbidden, "Token expired")
		return
	}

	// TODO: Check blocked refresh token

	// Check if it's time to issue new refresh token
	if timeDiff < REF_TOKEN_MIN_TTL.Seconds() {
		// Issue new refresh token
		jwtStr, jwtClaim, err := c.tokenService.IssueToken(refreshJWT.UserID, schema.RefreshTokenType)
		if err != nil {
			ctx.AbortWithError(http.StatusBadGateway, err)
		}
		now := time.Now().Unix()

		// Set new refresh token
		for _, domain := range c.domains {
			ctx.SetCookie("rfTk", jwtStr, int(jwtClaim.Expiry.Time().Unix()-now), "/user", domain, false, true)
		}
	}

	// Issue new access token
	jwtStr, jwtClaim, err := c.tokenService.IssueToken(refreshJWT.UserID, schema.AccessTokenType)
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err)
	}
	now := time.Now().Unix()

	// Set new access token
	for _, domain := range c.domains {
		ctx.SetCookie("acTk", jwtStr, int(jwtClaim.Expiry.Time().Unix()-now), "/", domain, false, true)
	}
}
