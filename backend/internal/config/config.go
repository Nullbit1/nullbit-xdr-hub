package config

import (
	"os"
)

type Config struct {
	HTTPAddr   string
	DBDSN      string
	RulesPath  string
	UsersPath  string
	JWTSecret  string
	IngestToken string
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func Load() Config {
	cfg := Config{
		HTTPAddr:   getenv("SENTRACORE_HTTP_ADDR", ":8080"),
		DBDSN:      getenv("SENTRACORE_DB_DSN", "postgres://sentracore:sentracore@localhost:5432/sentracore?sslmode=disable"),
		RulesPath:  getenv("SENTRACORE_RULES_PATH", "config/rules.yaml"),
		UsersPath:  getenv("SENTRACORE_USERS_PATH", "config/users.yaml"),
		JWTSecret:  os.Getenv("SENTRACORE_JWT_SECRET"),
		IngestToken: os.Getenv("SENTRACORE_INGEST_TOKEN"),
	}
	if cfg.JWTSecret == "" {
		cfg.JWTSecret = "dev-secret-change-me"
	}
	return cfg
}
