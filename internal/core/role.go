package core

import "time"

type Role struct {
	ID          string    `json:"-" db:"id" valid:"require"`
	Name        string    `json:"name" db:"name" valid:"require"`
	Description string    `json:"description" db:"description"`
	IsDefault   bool      `json:"is_default" db:"is_default"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type Permission struct {
	ID          string    `json:"-" db:"id" valid:"require"`
	Name        string    `json:"name" db:"name" valid:"require"`
	Description string    `json:"description" db:"description"`
	IsDefault   bool      `json:"is_default" db:"is_default"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type PermissionElement struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type RoleElement struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Permissions []PermissionElement `json:"permissions"`
}
