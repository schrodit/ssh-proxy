package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// Config represents the main configuration structure
type Config struct {
	Routes []Route `yaml:"routes"`
}

// Route represents a routing rule for a specific username
type Route struct {
	Username string       `yaml:"username"`
	Target   Target       `yaml:"target"`
	Auth     []AuthMethod `yaml:"auth"`
}

// AuthMethod represents an authentication method for client connections
type AuthMethod struct {
	Type           string   `yaml:"type"`                      // "password", "key", or "password_hash"
	Password       string   `yaml:"password,omitempty"`        // for password auth (plain text)
	PasswordHash   string   `yaml:"password_hash,omitempty"`   // for hashed password auth
	HashType       string   `yaml:"hash_type,omitempty"`       // hash algorithm used (bcrypt, sha256, etc.)
	AuthorizedKeys []string `yaml:"authorized_keys,omitempty"` // for key auth (inline public keys)
}

// Target represents the target SSH server configuration
type Target struct {
	Host string     `yaml:"host"`
	Port int        `yaml:"port"`
	User string     `yaml:"user"`
	Auth TargetAuth `yaml:"auth"`
}

// TargetAuth represents authentication configuration for target server connections
type TargetAuth struct {
	Type     string `yaml:"type"`     // "password", "key", or "password_hash"
	Password string `yaml:"password"` // for password auth (plain text)
	KeyPath  string `yaml:"key_path"` // for key auth (file path)
}

// Load reads and parses a configuration file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}
