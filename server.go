// Copyright (c) 2021 Satvik Reddy
package main

import (
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/joho/godotenv/autoload"
)

// ConfigData is the parsed version of the .env file
type ConfigData struct {
	AccessTokenSecret  []byte
	RefreshTokenSecret []byte
}

// Config holds the server configuration
var Config ConfigData

// LoadConfig loads configuration data from a .env file
func LoadConfig() {
	Config = ConfigData{
		[]byte(os.Getenv("ACCESS_TOKEN_SECRET")),
		[]byte(os.Getenv("REFRESH_TOKEN_SECRET")),
	}
}

func main() {
	LoadConfig()
	r := gin.Default()
	authRoutes := r.Group("/")
	authRoutes.Use(JWTAuth())

	r.POST("/login", Login)
	r.POST("/signup", Signup)
	r.DELETE("/logout", Logout)
	r.PUT("/refresh", Refresh)

	authRoutes.GET("/me", Me)

	corsConfig := cors.DefaultConfig()
	// Wherever your frontend is runnning
	corsConfig.AllowOrigins = []string{"http://localhost:3000"}
	corsConfig.AllowCredentials = true
	corsConfig.AllowHeaders = []string{
		"Origin",
		"Content-Length",
		"Content-Type",
		"Authorization",
	}
	r.Use(cors.New(corsConfig))

	r.Run(":8001")
}
