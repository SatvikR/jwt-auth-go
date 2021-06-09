// Copyright (c) 2021 Satvik Reddy
package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/joho/godotenv/autoload"
)

type TokenType int

type TokenClaims struct {
	Uid       string `json:"uid"`
	TokenType string `json:"tokenType"`
	jwt.StandardClaims
}

type Config struct {
	AccessTokenSecret  []byte
	RefreshTokenSecret []byte
}

type SignupBody struct {
	Username string `json:"username"`
}

type LoginBody struct {
	Username string `json:"username"`
}

type LogoutBody struct {
	Token string `json:"token"`
}

type RefreshBody struct {
	Token string `json:"token"`
}

type AuthHeader struct {
	Authorization string `header:"Authorization"`
}

const (
	AccessToken         TokenType = iota
	RefreshToken        TokenType = iota
	AccessString        string    = "access"
	RefreshString       string    = "refresh"
	RefreshCookieString string    = "rtoken"
)

var users []*User
var config Config

type User struct {
	Username string
	Uid      string
}

func LoadConfig() {
	config = Config{
		[]byte(os.Getenv("ACCESS_TOKEN_SECRET")),
		[]byte(os.Getenv("REFRESH_TOKEN_SECRET")),
	}
}

func GetExpTime(expiresIn int64) int64 {
	return time.Now().Unix() + expiresIn
}

func CreateUser(username string) string {
	newUser := &User{
		username,
		uuid.New().String(),
	}

	users = append(users, newUser)

	return newUser.Uid
}

func GenerateToken(tokenType TokenType, claims TokenClaims) (string, error) {
	var secret []byte
	if tokenType == AccessToken {
		secret = config.AccessTokenSecret
	} else {
		secret = config.RefreshTokenSecret
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(secret)
	return signedToken, err
}

func VerifyToken(signedString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		signedString,
		&TokenClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if claims, ok := token.Claims.(*TokenClaims); ok {
				if claims.TokenType == AccessString {
					return config.AccessTokenSecret, nil
				}
				if claims.TokenType == RefreshString {
					return config.RefreshTokenSecret, nil
				}
				return nil, errors.New("invalid tokenType")
			}
			return nil, errors.New("invalid claims")
		},
	)

	if err != nil {
		return &TokenClaims{}, err
	}
	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims, nil
	}
	return &TokenClaims{}, errors.New("inavlid token")

}

func GenerateTokenPair(uid string) (string, string, error) {
	accessToken, err := GenerateToken(AccessToken, TokenClaims{
		uid,
		AccessString,
		jwt.StandardClaims{
			ExpiresAt: GetExpTime(15),
		},
	})
	if err != nil {
		return "", "", err
	}

	refreshToken, err := GenerateToken(RefreshToken, TokenClaims{
		uid,
		RefreshString,
		jwt.StandardClaims{
			ExpiresAt: GetExpTime(7 * 24 * 60 * 60),
		},
	})
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		var header AuthHeader
		if err := c.ShouldBindHeader(&header); err != nil {
			c.JSON(http.StatusBadRequest, &gin.H{
				"error": "invalid header",
			})
			c.Abort()
			return
		}

		var signedToken string
		if bearer := strings.Split(header.Authorization, " "); len(bearer) == 2 {
			signedToken = bearer[1]
		} else {
			c.JSON(http.StatusBadRequest, &gin.H{
				"error": "headers: invalid bearer",
			})
			c.Abort()
			return
		}

		claims, err := VerifyToken(signedToken)
		if err != nil {
			c.JSON(http.StatusBadRequest, &gin.H{
				"error": "invalid token",
			})
			c.Abort()
			return
		}

		if claims.TokenType != AccessString {
			c.JSON(http.StatusBadRequest, &gin.H{
				"error": "invalid token type",
			})
			c.Abort()
			return
		}
		c.Set("claims", claims)
		c.Next()
	}
}

func SetRefreshToken(c *gin.Context, token string) {
	c.SetCookie(RefreshCookieString, token, 7*24*60*60, "/refresh", "localhost", false, true)
}

func Login(c *gin.Context) {
	var reqBody LoginBody
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, &gin.H{
			"error": "invalid request body",
		})
		return
	}

	var user *User
	for _, u := range users {
		if u.Username == reqBody.Username {
			user = u
			break
		}
	}

	if user == nil {
		c.JSON(http.StatusBadRequest, &gin.H{
			"error": "unable to find username",
		})
		return
	}

	accessToken, refreshToken, err := GenerateTokenPair(user.Uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to generate tokens",
		})
	}

	SetRefreshToken(c, refreshToken)
	c.JSON(http.StatusCreated, &gin.H{
		"accessToken": accessToken,
	})
}

func Signup(c *gin.Context) {
	var reqBody SignupBody
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, &gin.H{
			"error": "invalid request body",
		})
		return
	}

	for _, u := range users {
		if u.Username == reqBody.Username {
			c.JSON(http.StatusBadRequest, &gin.H{
				"error": "user already exists",
			})
			return
		}
	}
	uid := CreateUser(reqBody.Username)

	accessToken, refreshToken, err := GenerateTokenPair(uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to generate tokens",
		})
		return
	}
	SetRefreshToken(c, refreshToken)

	c.JSON(http.StatusCreated, &gin.H{
		"accessToken": accessToken,
	})
}

func Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie(RefreshCookieString)
	if err != nil || refreshToken == "" {
		c.JSON(http.StatusBadRequest, &gin.H{
			"error": "token invalid",
		})
		return
	}

	claims, err := VerifyToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, &gin.H{
			"error": "token invalid",
		})
		return
	}

	accessToken, refreshToken, err := GenerateTokenPair(claims.Uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create token",
		})
		return
	}

	SetRefreshToken(c, refreshToken)
	c.JSON(http.StatusOK, &gin.H{
		"accessToken": accessToken,
	})
}

func Logout(c *gin.Context) {
	SetRefreshToken(c, "")

	c.JSON(http.StatusOK, &gin.H{
		"message": "logout successful",
	})
}

func Me(c *gin.Context) {
	rawClaims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "could not retrieve token claims",
		})
		return
	}
	claims := rawClaims.(*TokenClaims)

	var username string
	for _, u := range users {
		if u.Uid == claims.Uid {
			username = u.Username
			break
		}
	}

	if username == "" {
		c.JSON(http.StatusBadRequest, &gin.H{
			"error": "cannot find user",
		})
		return
	}

	c.JSON(http.StatusOK, &gin.H{
		"message": fmt.Sprintf("Your username is %s", username),
	})
}

func main() {
	LoadConfig()
	r := gin.Default()
	authRoutes := r.Group("/")
	authRoutes.Use(JWTAuth())

	r.POST("/login", Login)
	r.POST("/signup", Signup)
	r.POST("/logout", Logout)
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
