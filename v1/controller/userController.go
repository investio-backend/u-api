package controller

import (
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
	"gitlab.com/investio/backend/user-api/v1/schema"
	"gitlab.com/investio/backend/user-api/v1/service"
	"golang.org/x/crypto/bcrypt"
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

type UserController interface {
	Login(ctx *gin.Context)
	LogOut(ctx *gin.Context)
	Refresh(ctx *gin.Context)
	CreateUser(ctx *gin.Context)
}

type userController struct {
	tokenService service.TokenService
	authService  service.AuthService
	redisService service.RedisService
	// domains      []string
}

func NewUserController(tokenService service.TokenService, authService service.AuthService, redisService service.RedisService) UserController {
	return &userController{
		tokenService: tokenService,
		authService:  authService,
		redisService: redisService,
		// TODO: Remove 192.168.50.233
		// domains: []string{"dewkul.me", "192.168.50.233"},
	}
}

func (c *userController) Login(ctx *gin.Context) {
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
		log.Fatal("Failed create token: ", err.Error())
		ctx.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	// if _, acsDiffExp := c.authService.IsExpired()

	// now := time.Now().Unix()

	// TODO: Rm 192.168.50.233
	// for _, domain := range c.domains {
	// 	ctx.SetCookie("acTk", tokens.AccessToken, int(tokens.AcsExpires-now), "/", domain, false, false)
	// 	ctx.SetCookie("rfTk", tokens.RefreshToken, int(tokens.RefExpires-now), "/user", domain, false, true)
	// }

	// ctx.JSON(http.StatusOK, "hello") // TODO: Return user info
	ctx.JSON(http.StatusOK, gin.H{
		"acc":   tokens.AccessToken,
		"a_exp": tokens.AcsExpires,
		"ref":   tokens.RefreshToken,
		// "r_exp":    tokens.RefExpires,
		"uid":      3,
		"username": "LnwTarn",
	})
}

type aTkRequest struct {
	AccessToken  string `json:"acc"`
	RefreshToken string `json:"ref"`
}

func (c *userController) LogOut(ctx *gin.Context) {
	// Get access token  // accessStr, err := ctx.Cookie("acTk")
	var reqBody aTkRequest

	if err := ctx.ShouldBindJSON(&reqBody); err != nil {
		// fmt.Println("Bind err ", err.Error())
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// fmt.Println("Logout - access = ", accessStr)

	_, accessJWT, err := c.authService.DecodeToken(reqBody.AccessToken)
	if err != nil {
		ctx.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	// // Remove access token from client
	// for _, domain := range c.domains {
	// 	ctx.SetCookie("acTk", "bye", -1, "/", domain, false, true)
	// }

	// TODO: Check blocked access token

	// Get Refresh Token
	// refreshStr, err := ctx.Cookie("rfTk")

	_, refreshJWT, err := c.authService.DecodeToken(reqBody.RefreshToken)
	if err != nil {
		ctx.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	if isExp, _ := c.authService.IsExpired(refreshJWT); isExp {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// // Remove refresh token from client
	// for _, domain := range c.domains {
	// 	ctx.SetCookie("rfTk", "bye", -1, "/user", domain, false, true)
	// }

	// Add tokens to blocklist
	tokenDetail := &schema.TokenDetail{
		AccessUuid:  accessJWT.Claims.ID,
		RefreshUuid: refreshJWT.Claims.ID,
		AtExpires:   int64(*accessJWT.Claims.Expiry),
		RtExpires:   int64(*refreshJWT.Claims.Expiry),
	}

	if accessJWT.UserID != refreshJWT.UserID {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		log.Println("Invalid access != refresh ", accessJWT.UserID, refreshJWT.UserID)
		return
	}

	// Block both access & refresh tokens
	if err := c.redisService.BlockTokens(accessJWT.UserID, tokenDetail); err != nil {
		ctx.AbortWithError(http.StatusBadGateway, err)
		log.Println("Redis: ", err.Error())
		return
	}

	ctx.JSON(http.StatusOK, "Logged out")
}

type rTkRequest struct {
	RefreshToken string `json:"ref"`
}

func (c *userController) Refresh(ctx *gin.Context) {
	REF_TOKEN_MIN_TTL := time.Minute * 10
	var reqBody rTkRequest

	// Get refresh token  // refreshStr, err := ctx.Cookie("rfTk")
	if err := ctx.ShouldBind(&reqBody); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	_, refreshJWT, err := c.authService.DecodeToken(reqBody.RefreshToken)
	if err != nil {
		ctx.AbortWithError(http.StatusForbidden, err)
		return
	}

	isExp, timeDiff := c.authService.IsExpired(refreshJWT)
	if isExp {
		ctx.AbortWithStatusJSON(http.StatusForbidden, "Token expired")
		return
	}

	refreshToken := reqBody.RefreshToken

	// TODO: Check blocked refresh token

	// Check if it's time to issue new refresh token
	if timeDiff < REF_TOKEN_MIN_TTL.Seconds() {
		// Issue new refresh token
		jwtStr, _, err := c.tokenService.IssueToken(refreshJWT.UserID, schema.RefreshTokenType)

		if err != nil {
			ctx.AbortWithError(http.StatusBadGateway, err)
		}
		// now := time.Now().Unix()

		// Set new refresh token
		refreshToken = jwtStr

		// for _, domain := range c.domains {
		// 	ctx.SetCookie("rfTk", jwtStr, int(jwtClaim.Expiry.Time().Unix()-now), "/user", domain, false, true)
		// }
	}

	// Issue new access token
	jwtStr, accessJwtClaim, err := c.tokenService.IssueToken(refreshJWT.UserID, schema.AccessTokenType)
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err)
	}
	// now := time.Now().Unix()

	// Set new access token
	accessToken := jwtStr
	// for _, domain := range c.domains {
	// 	ctx.SetCookie("acTk", jwtStr, int(jwtClaim.Expiry.Time().Unix()-now), "/", domain, false, true)
	// }

	ctx.JSON(http.StatusOK, gin.H{
		"acc":   accessToken,
		"a_exp": accessJwtClaim.Expiry.Time().Unix(),
		"ref":   refreshToken,
	})
}

type createUserReq struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (c *userController) CreateUser(ctx *gin.Context) {
	var reqBody createUserReq
	if err := ctx.ShouldBindJSON(&reqBody); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	hashByte, err := bcrypt.GenerateFromPassword([]byte(reqBody.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, err.Error())
	}
	hashPwd := string(hashByte)
	log.Info("Hash: ", string(hashPwd))
	ctx.Status(200)
}
