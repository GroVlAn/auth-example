package core

import "time"

type AuthUser struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type User struct {
	ID           string    `json:"_" db:"id" valid:"require"`
	Username     string    `json:"username" db:"username" valid:"require"`
	Email        string    `json:"email" db:"email" valid:"require"`
	Password     string    `json:"password" db:"-" valid:"require"`
	PasswordHash string    `json:"-" db:"password_hash"`
	FullName     string    `json:"full_name" db:"full_name" valid:"require"`
	CreatedAt    time.Time `json:"create_at" db:"created_at"`
}

type UserRequest struct {
	ID       string `json:"id" valid:"optional"`
	Username string `json:"username" valid:"optional"`
	Email    string `json:"email" valid:"optional"`
}
