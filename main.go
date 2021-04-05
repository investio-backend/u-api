package main

import (
	"context"
	"log"
	"os"

	_ "time/tzdata"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gitlab.com/investio/backend/user-api/v1/controller"
	"gitlab.com/investio/backend/user-api/v1/service"
)

var (
	tokenService service.TokenService = service.NewTokenService()
	authService  service.AuthService  = service.NewAuthService()
	redisService service.RedisService = service.NewRedisService(context.Background())

	tokenController controller.TokenController = controller.NewTokenController(tokenService, authService, redisService)
)

func main() {
	if os.Getenv("GIN_MODE") != "release" {
		err := godotenv.Load()
		if err != nil {
			log.Fatal("Error loading .env file")
			return
		}
	}

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
		v1.POST("/logout", tokenController.LogOut)
		v1.POST("/refresh", tokenController.Refresh)
	}
	port := os.Getenv("API_PORT")
	if port == "" {
		port = "5005"
	}
	log.Fatal(server.Run(":" + port))
}
