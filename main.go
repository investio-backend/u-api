package main

import (
	"context"
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gitlab.com/investio/backend/user-api/v1/controller"
	"gitlab.com/investio/backend/user-api/v1/service"
)

// "github.com/gin-contrib/cors"
// "github.com/gin-gonic/gin"

var (
	tokenService service.TokenService = service.NewTokenService()
	authService  service.AuthService  = service.NewAuthService()
	redisService service.RedisService = service.NewRedisService(context.Background())

	tokenController controller.TokenController = controller.NewTokenController(tokenService, authService, redisService)
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
		return
	}

	// tokens, _ := tokenService.CreateTokens("4")
	// fmt.Println(tokens.AccessToken)

	// // testToken := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MTcyODA3MjUsImlhdCI6MTYxNzI4MDY2NSwiaXNfYXV0aG9yaXplZCI6dHJ1ZSwiaXNfcmVmcmVzaCI6ZmFsc2UsImlzcyI6Imlzc3VlcjEiLCJqdGkiOiJjY2RkNWMxYS02ZTdkLTRiZWQtYWUzNC05M2VjYTgyOWMyNmYiLCJzdWIiOiJzdWJqZWN0MSIsInVzZXJfaWQiOiI0In0.pLBmjXIqGxWD-ec7EVMSdVAd2OSI_Cy3NXvYTY1Y0TCKVab1OMaMjUaxTM2jso4e7ldKs8C8dl_zk2aXay7vCQ"
	// // detail, err := authService.DecodeToken(testToken)
	// detail, err := authService.DecodeToken(tokens.AccessToken)
	// if err != nil {
	// 	fmt.Println("ERR: ", err.Error())
	// }
	// fmt.Println(detail.IsAuthorized)

	if err := redisService.TestConnection(); err != nil {
		panic(err)
	}

	server := gin.Default()

	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"http://localhost:8080", "http://192.168.50.121:3003", "https://investio.dewkul.me", "https://investio.netlify.app"}
	// To be able to send tokens to the server.
	corsConfig.AllowCredentials = true

	// OPTIONS method for VueJS
	corsConfig.AddAllowMethods("OPTIONS")
	server.Use(cors.New(corsConfig))

	v1 := server.Group("/user/v1")
	{
		v1.POST("/login", tokenController.Login)
		v1.GET("/logout", tokenController.LogOut)
		v1.GET("/refresh", tokenController.Refresh)
	}
	log.Fatal(server.Run(":" + os.Getenv("USER_API_PORT")))
}
