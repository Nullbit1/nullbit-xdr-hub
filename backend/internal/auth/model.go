package auth

import "time"

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleAnalyst  Role = "analyst"
	RoleReadOnly Role = "read_only"
)

type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	PasswordHash string `json:"-"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}
