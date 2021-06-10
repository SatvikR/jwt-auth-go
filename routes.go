// Copyright (c) 2021 Satvik Reddy
package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// SignupBody holds the info needed to create a user
type SignupBody struct {
	Username string `json:"username"`
}

// LoginBody holds the info needed to login a user
type LoginBody struct {
	Username string `json:"username"`
}

// AuthHeader holds the authorization headers needed to make authenticated requests
type AuthHeader struct {
	Authorization string `header:"Authorization"`
}

// Login handles the `/login` route
func Login(c *gin.Context) {
	var reqBody LoginBody
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, &gin.H{
			"error": "invalid request body",
		})
		return
	}

	var user *User
	for _, u := range Users {
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

// Signup handles the `/signup` route
func Signup(c *gin.Context) {
	var reqBody SignupBody
	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, &gin.H{
			"error": "invalid request body",
		})
		return
	}

	for _, u := range Users {
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

// Refresh handles the `/refresh` route
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

// Logout handles `/logout`.
// It clears the refresh token cookie
func Logout(c *gin.Context) {
	SetRefreshToken(c, "")

	c.JSON(http.StatusOK, &gin.H{
		"message": "logout successful",
	})
}

// Me handles `/me`
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
	for _, u := range Users {
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
