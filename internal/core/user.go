package core

import "time"

type AuthUser struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type User struct {
	ID           string    `json:"-" db:"id" valid:"require"`
	Username     string    `json:"username" db:"username" valid:"require"`
	Email        string    `json:"email" db:"email" valid:"require"`
	Password     string    `json:"password" db:"-" valid:"require"`
	PasswordHash string    `json:"-" db:"password_hash"`
	Fullname     string    `json:"fullname" db:"fullname" valid:"require"`
	CreatedAt    time.Time `json:"create_at" db:"created_at"`
	IsSuperuser  bool      `json:"is_superuser" db:"is_superuser"`
	IsActive     bool      `json:"is_active" db:"is_active"`
	RoleID       string    `json:"-" db:"role_id"`
}

type UserRequest struct {
	ID       string `json:"id" valid:"optional"`
	Username string `json:"username" valid:"optional"`
	Email    string `json:"email" valid:"optional"`
}
