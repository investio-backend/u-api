package main

import (
	"context"
	"os"

	"github.com/sirupsen/logrus"

	_ "time/tzdata"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gitlab.com/investio/backend/user-api/db"
	"gitlab.com/investio/backend/user-api/v1/controller"
	"gitlab.com/investio/backend/user-api/v1/service"
)

var (
	log = logrus.New()

	tokenService = service.NewTokenService()
	authService  = service.NewAuthService()
	redisService = service.NewRedisService(context.Background())
	userService  = service.NewUserService()

	userController = controller.NewUserController(tokenService, authService, redisService, userService)
)

func main() {
	if os.Getenv("GIN_MODE") != "release" {
		err := godotenv.Load()
		if err != nil {
			log.Warn("Main: Not using .env file")
		}
	}

	if err := db.SetupDB(); err != nil {
		log.Panic(err)
	}

	if err := redisService.TestConnection(); err != nil {
		log.Panic(err)
	}

	// r := gin.New()
	// r.Use(ginlogrus.Logger(log), gin.Recovery())
	r := gin.Default()

	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"http://localhost:2564", "http://192.168.50.121:3003", "https://investio.dewkul.me", "https://investio.netlify.app"}
	// To be able to send tokens to the server.
	corsConfig.AllowCredentials = true

	// OPTIONS method for VueJS
	corsConfig.AddAllowMethods("OPTIONS")
	r.Use(cors.New(corsConfig))

	v1 := r.Group("/user/v1")
	{
		v1.POST("/login", userController.Login)
		v1.POST("/logout", userController.LogOut)
		v1.POST("/refresh", userController.Refresh)
		v1.POST("/create", userController.RegisterUser)
		v1.GET("/data", userController.GetUserData)
		v1.GET("/data/risk", userController.GetRiskScore)
		v1.POST("/data/risk", userController.UpdateRiskScore)
		// data := r.Group("/data")
		// {
		// 	data.GET("/risk", userController.GetRiskScore)
		// 	data.POST("/risk", userController.UpdateRiskScore)
		// }
	}
	port := os.Getenv("API_PORT")
	if port == "" {
		port = "5005"
	}
	log.Panic(r.Run(":" + port))
}
