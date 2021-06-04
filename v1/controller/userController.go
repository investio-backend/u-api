package controller

import (
	"errors"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/gin-gonic/gin"
	"gitlab.com/investio/backend/user-api/v1/model"
	"gitlab.com/investio/backend/user-api/v1/schema"
	"gitlab.com/investio/backend/user-api/v1/service"
	"golang.org/x/crypto/bcrypt"
)

// type User struct {
// 	ID       string `json:"id"`
// 	Username string `json:"username"`
// 	Password string `json:"password"`
// }

//A sample use
// var user = User{
// 	ID:       "46",
// 	Username: "LnwTarn",
// 	Password: "CrazyTarnny",
// }

type UserController interface {
	Login(ctx *gin.Context)
	LogOut(ctx *gin.Context)
	Refresh(ctx *gin.Context)
	RegisterUser(ctx *gin.Context)
	GetUserData(ctx *gin.Context)
	GetRiskScore(ctx *gin.Context)
	UpdateRiskScore(ctx *gin.Context)
}

type userController struct {
	tokenService service.TokenService
	authService  service.AuthService
	redisService service.RedisService
	userService  service.UserService
	// domains      []string
}

func NewUserController(tokenService service.TokenService, authService service.AuthService, redisService service.RedisService, userService service.UserService) UserController {
	return &userController{
		tokenService: tokenService,
		authService:  authService,
		redisService: redisService,
		userService:  userService,
		// TODO: Remove 192.168.50.233
		// domains: []string{"dewkul.me", "192.168.50.233"},
	}
}

type allTokensBody struct {
	AccessToken  string `json:"acc"`
	RefreshToken string `json:"ref"`
}

// type accessTokenBody struct {
// 	AccessToken string `json:"acc"`
// }

type refreshTokenBody struct {
	RefreshToken string `json:"ref"`
}

type userReqBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c *userController) Login(ctx *gin.Context) {
	// var u User
	var (
		req  userReqBody
		user model.User
	)

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, "Invalid data provided")
		return
	}
	// //compare the user from the request, with the one we defined:
	// if user.Username != u.Username || user.Password != u.Password {
	// 	ctx.JSON(http.StatusForbidden, "Invalid login credentials")
	// 	return
	// }

	// Get user from DB
	if err := c.userService.GetByUsername(&user, req.Username); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.AbortWithStatus(http.StatusNotFound)
		}
		ctx.AbortWithError(http.StatusBadRequest, err)
		return
	}

	// Compare user
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashPwd), []byte(req.Password)); err != nil {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	tokens, err := c.tokenService.CreateTokens(user.ID)
	if err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, err.Error())
		log.Fatal("Failed create token: ", err.Error())
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
		"acc":      tokens.AccessToken,
		"a_exp":    tokens.AcsExpires,
		"ref":      tokens.RefreshToken,
		"uid":      user.ID,
		"username": user.Name,
		// "r_exp":    tokens.RefExpires,
	})
}

func (c *userController) LogOut(ctx *gin.Context) {
	// Get access token  // accessStr, err := ctx.Cookie("acTk")
	var reqBody allTokensBody

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

func (c *userController) Refresh(ctx *gin.Context) {
	REF_TOKEN_MIN_TTL := time.Minute * 10
	var reqBody refreshTokenBody

	// Get refresh token  // refreshStr, err := ctx.Cookie("rfTk")
	if err := ctx.ShouldBindJSON(&reqBody); err != nil {
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
		"uid":   accessJwtClaim.UserID,
	})
}

type createUserReq struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (c *userController) RegisterUser(ctx *gin.Context) {
	var reqBody createUserReq

	if err := ctx.ShouldBindJSON(&reqBody); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"reason": "bad request",
		})
		return
	}

	if len(reqBody.Username) < 5 || len(reqBody.Password) < 6 {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"reason": "username or password is too short",
		})
	}

	hashByte, err := bcrypt.GenerateFromPassword([]byte(reqBody.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.AbortWithError(http.StatusBadRequest, err)
		return
	}
	// hashPwd := string(hashByte)
	// log.Info("Hash: ", string(hashPwd))
	user := model.User{
		Name:    reqBody.Username,
		Email:   reqBody.Email,
		HashPwd: string(hashByte),
	}

	if err := c.userService.Create(&user); err != nil {
		// var mysqlErr mysql.MySQLError
		// if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {

		// }
		ctx.AbortWithError(http.StatusBadRequest, err)
		return
	}

	log.Info("Uid ", user.ID)
	ctx.JSON(http.StatusOK, user)
}

func (c *userController) GetUserData(ctx *gin.Context) {
	var (
		// reqBody  accessTokenBody
		userData model.UserData
	)

	// Get access token
	accessJWT, errReason := c.authService.ValidateAccessToken(ctx.Request)
	if errReason != "" {
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"reason": errReason,
		})
		return
	}

	// accessToken := c.authService.ExtractHeader(ctx.Request)
	// // if err := ctx.ShouldBindJSON(&reqBody); err != nil {
	// // 	ctx.AbortWithStatus(http.StatusBadRequest)
	// // 	return
	// // }

	// if accessToken == "" {
	// 	ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
	// 		"reason": "",
	// 	})
	// 	return
	// }

	// _, accessJWT, err := c.authService.DecodeToken(accessToken)
	// if err != nil {
	// 	ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
	// 		"reason": err.Error(),
	// 	})
	// 	return
	// }

	// if accessJWT.IsRefresh {
	// 	ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
	// 		"reason": "token is invalid",
	// 	})
	// 	return
	// }

	// isExp, _ := c.authService.IsExpired(accessJWT)
	// if isExp {
	// 	ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
	// 		"reason": "Token expired",
	// 	})
	// 	return
	// }

	if err := c.userService.GetUserData(&userData, accessJWT.UserID); err != nil {
		ctx.AbortWithError(http.StatusBadRequest, err)
		return
	}

	ctx.JSON(http.StatusOK, userData)
}

func (c *userController) GetRiskScore(ctx *gin.Context) {
	// var reqBody accessTokenBody
	var accessJWT *schema.TokenClaims

	// Get access token
	// if err := ctx.ShouldBindJSON(&reqBody); err != nil {
	// 	ctx.AbortWithStatus(http.StatusBadRequest)
	// 	return
	// }

	// _, accessJWT, err := c.authService.DecodeToken(reqBody.AccessToken)
	// if err != nil {
	// 	ctx.AbortWithError(http.StatusForbidden, err)
	// 	return
	// }

	// isExp, _ := c.authService.IsExpired(accessJWT)
	// if isExp {
	// 	ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
	// 		"reason": "Token expired",
	// 	})
	// 	return
	// }

	accessJWT, errReason := c.authService.ValidateAccessToken(ctx.Request)
	if errReason != "" {
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"reason": errReason,
		})
	}

	risk, updatedAt, err := c.userService.GetRiskScore(accessJWT.UserID)
	if err != nil {
		ctx.AbortWithError(http.StatusBadGateway, err)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"risk_score":   risk,
		"last_updated": updatedAt,
	})
}

type updateRiskBody struct {
	// AccessToken string `json:"acc"`
	RiskScore uint8 `json:"risk_score"`
}

func (c *userController) UpdateRiskScore(ctx *gin.Context) {
	var reqBody updateRiskBody

	// Get access token
	accessJWT, errReason := c.authService.ValidateAccessToken(ctx.Request)
	if errReason != "" {
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"reason": errReason,
		})
	}
	if err := ctx.ShouldBindJSON(&reqBody); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// _, accessJWT, err := c.authService.DecodeToken(reqBody.AccessToken)
	// if err != nil {
	// 	ctx.AbortWithError(http.StatusForbidden, err)
	// 	return
	// }

	// isExp, _ := c.authService.IsExpired(accessJWT)
	// if isExp {
	// 	ctx.AbortWithStatusJSON(http.StatusForbidden, "Token expired")
	// 	return
	// }

	// refreshToken := reqBody.RefreshToken

	if err := c.userService.SetRiskScore(accessJWT.UserID, reqBody.RiskScore); err != nil {
		ctx.AbortWithError(http.StatusBadGateway, err)
		return
	}

	ctx.Status(http.StatusOK)
}
