// Copyright (c) 2021 Satvik Reddy
package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// TokenType is used as an enum for the two token types
type TokenType int

const (
	// AccessToken is an enum type to represent an access token
	AccessToken TokenType = iota
	// RefreshToken is an enum type to represent a refresh token
	RefreshToken TokenType = iota
	// AccessString is the string reprentation of the access token type.
	// It is stored in the JWTs as a way to differentiate between token types.
	AccessString string = "access"
	// RefreshString is the string reprentation of the refresh token type.
	// It is stored in the JWTs as a way to differentiate between token types.
	RefreshString string = "refresh"
	// RefreshCookieString is the name of the cookie that holds the refresh tokens.
	RefreshCookieString string = "rtoken"
)

// TokenClaims contains the data stored within a JWT
type TokenClaims struct {
	Uid       string `json:"uid"`
	TokenType string `json:"tokenType"`
	jwt.StandardClaims
}

// GetExpTime returns an epoch timestamp given a number seconds
func GetExpTime(expiresIn int64) int64 {
	return time.Now().Unix() + expiresIn
}

// GenerateToken will generate a signed jwt with claims
func GenerateToken(tokenType TokenType, claims TokenClaims) (string, error) {
	var secret []byte
	if tokenType == AccessToken {
		secret = Config.AccessTokenSecret
	} else {
		secret = Config.RefreshTokenSecret
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(secret)
	return signedToken, err
}

// VerifyToken will verify a signed JWT and return claims and an error
func VerifyToken(signedString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		signedString,
		&TokenClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if claims, ok := token.Claims.(*TokenClaims); ok {
				if claims.TokenType == AccessString {
					return Config.AccessTokenSecret, nil
				}
				if claims.TokenType == RefreshString {
					return Config.RefreshTokenSecret, nil
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

// GenerateTokenPair will create access and refresh tokens given a user id
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

// JWTAuth returns a middleware handler for jwt authentication
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

// SetRefrehToken sets the rtoken httpOnly cookie
func SetRefreshToken(c *gin.Context, token string) {
	c.SetCookie(RefreshCookieString, token, 7*24*60*60, "/refresh", "localhost", false, true)
}
