package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sync"
	"text/template"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/minio/sha256-simd"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Config represents the main configuration structure
type Config struct {
	Routes []Route `yaml:"routes"`
}

// Route represents a routing rule for a specific username
type Route struct {
	Username      string       `yaml:"username"`
	UsernameRegex string       `yaml:"usernameRegex,omitempty"`
	Target        Target       `yaml:"target"`
	Auth          []AuthMethod `yaml:"auth"`

	// compiledRegex is the compiled version of UsernameRegex (not serialized)
	compiledRegex *regexp.Regexp
}

// RouteMatch contains information about a matched route including any captured groups
type RouteMatch struct {
	Route  *Route
	Groups []string          // positional groups (index 0 = full match)
	Named  map[string]string // named capture groups
}

// AuthMethod represents an authentication method for client connections
type AuthMethod struct {
	Type           string         `yaml:"type"`                     // "password", "key", "password_hash", or "external_auth"
	Password       string         `yaml:"password,omitempty"`       // for password auth (plain text)
	PasswordHash   string         `yaml:"passwordHash,omitempty"`   // for hashed password auth
	HashType       string         `yaml:"hashType,omitempty"`       // hash algorithm used (bcrypt, sha256, etc.)
	AuthorizedKeys []string       `yaml:"authorizedKeys,omitempty"` // for key auth (inline public keys)
	ExternalAuth   *WebhookConfig `yaml:"externalAuth,omitempty"`   // for external auth via webhook
}

// Target represents the target SSH server configuration
type Target struct {
	Host     string     `yaml:"host"`
	Port     int        `yaml:"port"`
	User     string     `yaml:"user"`
	Auth     TargetAuth `yaml:"auth"`
	HostKey  string     `yaml:"hostKey"`  // known public key of the target server (e.g. "ssh-ed25519 AAAA..."); required if insecure is false
	Insecure bool       `yaml:"insecure"` // skip host key verification; must be explicitly true if hostKey is not set
}

// TargetAuth represents authentication configuration for target server connections
type TargetAuth struct {
	Type     string `yaml:"type"`     // "password", "key", or "password_hash"
	Password string `yaml:"password"` // for password auth (plain text)
	KeyPath  string `yaml:"keyPath"`  // for key auth (file path)
}

// WebhookConfig represents the configuration for an external authentication webhook.
// The webhook receives a JSON POST with user credentials and returns whether the
// user is authenticated.
type WebhookConfig struct {
	URL     string            `yaml:"url"`               // URL of the webhook endpoint
	Headers map[string]string `yaml:"headers,omitempty"` // optional HTTP headers (e.g., Authorization)
	Timeout string            `yaml:"timeout,omitempty"` // Go duration string (e.g., "5s", "30s"); default "5s"
}

func (o ServerAuthOption) IsEnabled() bool {
	return o.Enabled == nil || *o.Enabled
}

func (a ServerAuth) PasswordEnabled() bool {
	return a.Password.IsEnabled()
}

func (a ServerAuth) PublicKeyEnabled() bool {
	return a.PublicKey.IsEnabled()
}

func (a ServerAuth) KeyboardInteractiveEnabled() bool {
	return a.KeyboardInteractive.IsEnabled()
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
		if route.Username != "" {
			routeMap[route.Username] = route
		}
	}
	return routeMap
}

// FindRoute finds a matching route for the given username.
// It first checks for exact username matches, then falls back to regex matching.
// Returns a RouteMatch with the matched route and any captured groups, or nil if no match.
func (cm *ConfigManager) FindRoute(username string) *RouteMatch {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// First pass: exact username match
	for i := range cm.config.Routes {
		route := &cm.config.Routes[i]
		if route.Username != "" && route.Username == username {
			return &RouteMatch{
				Route:  route,
				Groups: nil,
				Named:  nil,
			}
		}
	}

	// Second pass: regex match
	for i := range cm.config.Routes {
		route := &cm.config.Routes[i]
		if route.compiledRegex == nil {
			continue
		}

		matches := route.compiledRegex.FindStringSubmatch(username)
		if matches == nil {
			continue
		}

		named := make(map[string]string)
		for j, name := range route.compiledRegex.SubexpNames() {
			if j > 0 && name != "" {
				named[name] = matches[j]
			}
		}

		return &RouteMatch{
			Route:  route,
			Groups: matches,
			Named:  named,
		}
	}

	return nil
}

// HostTemplateData is the data available to Go templates in the host field
type HostTemplateData struct {
	Username string
	Groups   []string
	Named    map[string]string
}

// ResolveHost resolves the target host, executing it as a Go template if it contains template syntax.
// The template has access to the username, positional groups, and named groups from the regex match.
func ResolveHost(host string, match *RouteMatch, username string) (string, error) {
	// Fast path: skip template parsing if no template syntax detected
	if !containsTemplateSyntax(host) {
		return host, nil
	}

	tmpl, err := template.New("host").Parse(host)
	if err != nil {
		return "", fmt.Errorf("failed to parse host template %q: %w", host, err)
	}

	data := HostTemplateData{
		Username: username,
		Groups:   match.Groups,
		Named:    match.Named,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute host template %q: %w", host, err)
	}

	resolved := buf.String()
	if resolved == "" {
		return "", fmt.Errorf("host template %q resolved to empty string", host)
	}

	return resolved, nil
}

// containsTemplateSyntax checks if a string contains Go template syntax
func containsTemplateSyntax(s string) bool {
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '{' && s[i+1] == '{' {
			return true
		}
	}
	return false
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

	// Validate and compile config
	if err := config.Validate(); err != nil {
		return nil, nil, err
	}

	return &config, data, nil
}

// Validate validates the configuration and compiles regex patterns.
func (c *Config) Validate() error {
	allErrs := field.ErrorList{}
	routesPath := field.NewPath("routes")
	serverAuthPath := field.NewPath("server", "auth")

	allErrs = append(allErrs, validateServerAuth(c.Server.Auth, serverAuthPath)...)

	for i := range c.Routes {
		route := &c.Routes[i]
		routePath := routesPath.Index(i)

		// Compile usernameRegex if set
		if route.UsernameRegex != "" {
			re, err := regexp.Compile(route.UsernameRegex)
			if err != nil {
				allErrs = append(allErrs, field.Invalid(routePath.Child("usernameRegex"), route.UsernameRegex, fmt.Sprintf("invalid regex: %v", err)))
			} else {
				route.compiledRegex = re
			}
		}

		// Validate auth methods
		for j, auth := range route.Auth {
			authPath := routePath.Child("auth").Index(j)
			allErrs = append(allErrs, validateAuthMethod(auth, authPath)...)
			allErrs = append(allErrs, validateAuthMethodEnabled(auth, c.Server.Auth, authPath)...)
		}

		// Validate that either hostKey or insecure is explicitly set
		targetPath := routePath.Child("target")
		if route.Target.HostKey == "" && !route.Target.Insecure {
			allErrs = append(allErrs, field.Required(targetPath.Child("hostKey"), "target must set either hostKey or insecure: true"))
		}
	}

	return allErrs.ToAggregate()
}

// validAuthTypes are the supported authentication method types.
var validAuthTypes = []string{"password", "key", "externalAuth"}

func validateServerAuth(auth ServerAuth, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if !auth.PasswordEnabled() && !auth.PublicKeyEnabled() && !auth.KeyboardInteractiveEnabled() {
		allErrs = append(allErrs, field.Invalid(fldPath, nil, "at least one server authentication method must be enabled"))
	}
	return allErrs
}

// validateAuthMethod validates a single auth method entry using field path errors.
func validateAuthMethod(auth AuthMethod, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	switch auth.Type {
	case "password":
		// Must have either password or passwordHash
		if auth.Password == "" && auth.PasswordHash == "" {
			allErrs = append(allErrs, field.Required(fldPath.Child("password"), "password or passwordHash is required for type \"password\""))
		}
		// If passwordHash is set, hashType must also be set
		if auth.PasswordHash != "" && auth.HashType == "" {
			allErrs = append(allErrs, field.Required(fldPath.Child("hashType"), "hashType is required when passwordHash is set"))
		}
		// Forbidden fields
		if len(auth.AuthorizedKeys) > 0 {
			allErrs = append(allErrs, field.Forbidden(fldPath.Child("authorizedKeys"), "not allowed for type \"password\""))
		}
		if auth.ExternalAuth != nil {
			allErrs = append(allErrs, field.Forbidden(fldPath.Child("externalAuth"), "not allowed for type \"password\""))
		}

	case "key":
		// Must have authorizedKeys
		if len(auth.AuthorizedKeys) == 0 {
			allErrs = append(allErrs, field.Required(fldPath.Child("authorizedKeys"), "required for type \"key\""))
		}
		// Forbidden fields
		if auth.Password != "" {
			allErrs = append(allErrs, field.Forbidden(fldPath.Child("password"), "not allowed for type \"key\""))
		}
		if auth.PasswordHash != "" {
			allErrs = append(allErrs, field.Forbidden(fldPath.Child("passwordHash"), "not allowed for type \"key\""))
		}
		if auth.HashType != "" {
			allErrs = append(allErrs, field.Forbidden(fldPath.Child("hashType"), "not allowed for type \"key\""))
		}
		if auth.ExternalAuth != nil {
			allErrs = append(allErrs, field.Forbidden(fldPath.Child("externalAuth"), "not allowed for type \"key\""))
		}

	case "external_auth":
		// Must have externalAuth config with url
		if auth.ExternalAuth == nil {
			allErrs = append(allErrs, field.Required(fldPath.Child("externalAuth"), "required for type \"external_auth\""))
		} else {
			extPath := fldPath.Child("externalAuth")
			if auth.ExternalAuth.URL == "" {
				allErrs = append(allErrs, field.Required(extPath.Child("url"), "webhook url is required"))
			}
			if auth.ExternalAuth.Timeout != "" {
				if _, err := time.ParseDuration(auth.ExternalAuth.Timeout); err != nil {
					allErrs = append(allErrs, field.Invalid(extPath.Child("timeout"), auth.ExternalAuth.Timeout, fmt.Sprintf("invalid duration: %v", err)))
				}
			}
		}
		// Forbidden fields
		if auth.Password != "" {
			allErrs = append(allErrs, field.Forbidden(fldPath.Child("password"), "not allowed for type \"external_auth\""))
		}
		if auth.PasswordHash != "" {
			allErrs = append(allErrs, field.Forbidden(fldPath.Child("passwordHash"), "not allowed for type \"external_auth\""))
		}
		if auth.HashType != "" {
			allErrs = append(allErrs, field.Forbidden(fldPath.Child("hashType"), "not allowed for type \"external_auth\""))
		}
		if len(auth.AuthorizedKeys) > 0 {
			allErrs = append(allErrs, field.Forbidden(fldPath.Child("authorizedKeys"), "not allowed for type \"external_auth\""))
		}

	case "":
		allErrs = append(allErrs, field.Required(fldPath.Child("type"), "auth type is required"))

	default:
		allErrs = append(allErrs, field.NotSupported(fldPath.Child("type"), auth.Type, validAuthTypes))
	}

	return allErrs
}

func validateAuthMethodEnabled(auth AuthMethod, serverAuth ServerAuth, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	switch auth.Type {
	case "password":
		if !serverAuth.PasswordEnabled() {
			allErrs = append(allErrs, field.Forbidden(fldPath, "server authentication method \"password\" is disabled"))
		}
	case "key":
		if !serverAuth.PublicKeyEnabled() {
			allErrs = append(allErrs, field.Forbidden(fldPath, "server authentication method \"publickey\" is disabled"))
		}
	case "externalAuth":
		if !serverAuth.PasswordEnabled() && !serverAuth.PublicKeyEnabled() && !serverAuth.KeyboardInteractiveEnabled() {
			allErrs = append(allErrs, field.Forbidden(fldPath, "externalAuth requires at least one enabled server authentication method: password, publickey, or keyboardInteractive"))
		}
	}

	return allErrs
}

// Load reads and parses a configuration file
func Load(path string) (*Config, error) {
	config, _, err := LoadWithData(path)
	return config, err
}
