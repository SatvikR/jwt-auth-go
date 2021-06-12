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
	Password string `json:"password"`
}

// LoginBody holds the info needed to login a user
type LoginBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
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

	user, err := GetUserIfValid(reqBody.Username, reqBody.Password)

	if err != nil {
		c.JSON(http.StatusBadRequest, &gin.H{
			"error": "username/password invalid",
		})
		return
	}

	accessToken, refreshToken, err := GenerateTokenPair(user.Id)
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

	_, err := GetUserIfExists(reqBody.Username)
	if err == nil {
		c.JSON(http.StatusBadRequest, &gin.H{
			"error": "user already exists",
		})
		return
	}
	if len(reqBody.Password) < 3 {
		c.JSON(http.StatusBadRequest, &gin.H{
			"error": "password must be at least 3 chars long",
		})
		return
	}

	encodedPw, err := Config.Argon.HashEncoded([]byte(reqBody.Password))
	if err != nil {
		c.JSON(http.StatusInternalServerError, &gin.H{
			"error": "unable to hash password",
		})
		return
	}
	uid, err := CreateUser(reqBody.Username, string(encodedPw))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create user",
		})
		return
	}

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

	accessToken, refreshToken, err := GenerateTokenPair(claims.UID)
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

	username, err := GetUsernameFromUid(claims.UID)

	if err != nil {
		c.JSON(http.StatusBadRequest, &gin.H{
			"error": "cannot find user",
		})
		return
	}

	c.JSON(http.StatusOK, &gin.H{
		"message": fmt.Sprintf("Your username is %s", username),
	})
}
