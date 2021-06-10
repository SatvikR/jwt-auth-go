// Copyright (c) 2021 Satvik Reddy
package main

import "github.com/google/uuid"

// Users holds references to all the users.
// Generally these would be stored in some kind of database
var Users []*User

// User holds all the user info
type User struct {
	Username string
	Uid      string
}

// CreateUser creates a user and saves it given a username.
// Returns the Uid
func CreateUser(username string) string {
	newUser := &User{
		username,
		uuid.New().String(),
	}

	Users = append(Users, newUser)

	return newUser.Uid
}
