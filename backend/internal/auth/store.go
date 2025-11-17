package auth

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

var ErrUserNotFound = errors.New("user not found")

func (s *Store) GetByUsername(ctx context.Context, username string) (*User, error) {
	const q = `SELECT id, username, password_hash, role, created_at FROM users WHERE username = $1`
	row := s.db.QueryRowContext(ctx, q, username)
	u := &User{}
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return u, nil
}

func (s *Store) Create(ctx context.Context, username, password string, role Role) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	const q = `
		INSERT INTO users (username, password_hash, role, created_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, username, password_hash, role, created_at
	`
	u := &User{}
	if err := s.db.QueryRowContext(ctx, q, username, string(hash), role, time.Now().UTC()).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt); err != nil {
		return nil, err
	}
	return u, nil
}

type usersFile struct {
	Users []struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Role     Role   `yaml:"role"`
	} `yaml:"users"`
}

func (s *Store) SeedFromFile(ctx context.Context, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var uf usersFile
	if err := yaml.Unmarshal(data, &uf); err != nil {
		return err
	}
	for _, u := range uf.Users {
		if u.Username == "" || u.Password == "" {
			continue
		}
		if _, err := s.GetByUsername(ctx, u.Username); err == nil {
			continue
		} else if !errors.Is(err, ErrUserNotFound) {
			return err
		}
		if _, err := s.Create(ctx, u.Username, u.Password, u.Role); err != nil {
			return err
		}
	}
	return nil
}
