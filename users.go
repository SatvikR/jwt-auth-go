// Copyright (c) 2021 Satvik Reddy
package main

import (
	"errors"

	"github.com/go-pg/pg/v10"
	"github.com/matthewhartstonge/argon2"
)

var DB *pg.DB

// User holds all the user info
type User struct {
	Username string
	Password string
	Id       string `pg:"type:uuid,default:uuid_generate_v4()"`
}

// CreateUser creates a user and saves it given a username and password.
// Returns the Uid
func CreateUser(username string, password string) (string, error) {
	newUser := &User{
		Username: username,
		Password: password,
	}
	_, err := DB.Model(newUser).Insert()
	if err != nil {
		return "", err
	}
	return newUser.Id, nil
}

// GetUserIfValid returns a user if it is valid, if not, returns an error
func GetUserIfValid(username string, password string) (*User, error) {
	user := new(User)
	err := DB.Model(user).
		Where("? = ?", pg.Ident("username"), username).
		Select()
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("user not found")
	}

	ok, err := argon2.VerifyEncoded([]byte(password), []byte(user.Password))
	if !ok || err != nil {
		return nil, errors.New("incorrect password")
	}
	return user, nil
}

// GetUserIfExists returns a user if the username is found.
func GetUserIfExists(username string) (*User, error) {
	user := new(User)
	err := DB.Model(user).
		Where("? = ?", pg.Ident("username"), username).
		Select()
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("user not found")
	}

	return user, nil
}

// GetUsernameFromUid returns a user's username based on their uid
func GetUsernameFromUid(uid string) (string, error) {
	user := new(User)
	err := DB.Model(user).
		Where("? = ?", pg.Ident("id"), uid).
		Select()
	if err != nil {
		return "", err
	}
	if user.Username == "" {
		return "", errors.New("user not found")
	}

	return user.Username, nil
}
