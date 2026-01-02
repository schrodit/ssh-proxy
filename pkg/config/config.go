package config

import (
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/minio/sha256-simd"
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

// ConfigManager manages configuration with dynamic reloading and concurrent access
type ConfigManager struct {
	mu         sync.RWMutex
	config     *Config
	path       string
	watcher    *fsnotify.Watcher
	closed     chan struct{}
	configHash [32]byte // SHA256 hash of current config content
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(path string) (*ConfigManager, error) {
	config, configData, err := LoadWithData(path)
	if err != nil {
		return nil, err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	cm := &ConfigManager{
		config:     config,
		path:       path,
		watcher:    watcher,
		closed:     make(chan struct{}),
		configHash: sha256.Sum256(configData),
	}

	// Add file to watcher
	if err := watcher.Add(path); err != nil {
		return nil, fmt.Errorf("failed to watch config file: %w", err)
	}

	// Start watching for file changes
	go cm.watchConfig()

	return cm, nil
}

// GetConfig returns the current configuration (concurrent-safe)
func (cm *ConfigManager) GetConfig() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config
}

// GetRouteMap returns a concurrent-safe copy of the route map
func (cm *ConfigManager) GetRouteMap() map[string]*Route {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	routeMap := make(map[string]*Route)
	for i := range cm.config.Routes {
		route := &cm.config.Routes[i]
		routeMap[route.Username] = route
	}
	return routeMap
}

// Close stops watching for config changes
func (cm *ConfigManager) Close() error {
	close(cm.closed)
	return cm.watcher.Close()
}

// watchConfig watches for file changes and reloads configuration
func (cm *ConfigManager) watchConfig() {
	for {
		select {
		case event := <-cm.watcher.Events:
			if event.Op&fsnotify.Write == fsnotify.Write {
				slog.Info("Config file changed, reloading", "file", event.Name)

				if err := cm.reloadConfig(); err != nil {
					slog.Error("Failed to reload config", "error", err)
				} else {
					slog.Info("Config reloaded successfully")
				}
			}
		case err := <-cm.watcher.Errors:
			slog.Error("Config file watcher error", "error", err)
		case <-cm.closed:
			return
		}
	}
}

// reloadConfig reloads the configuration from file (thread-safe)
func (cm *ConfigManager) reloadConfig() error {
	newConfig, configData, err := LoadWithData(cm.path)
	if err != nil {
		return err
	}

	// Calculate hash of new config data
	newHash := sha256.Sum256(configData)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Only update if hash has changed
	if newHash == cm.configHash {
		slog.Debug("Config file content unchanged, skipping reload")
		return nil
	}

	cm.config = newConfig
	cm.configHash = newHash
	slog.Info("Config content changed, configuration updated")

	return nil
}

// LoadWithData reads and parses a configuration file, returning both config and raw data
func LoadWithData(path string) (*Config, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, data, nil
}

// Load reads and parses a configuration file
func Load(path string) (*Config, error) {
	config, _, err := LoadWithData(path)
	return config, err
}
