package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config Package", func() {
	Describe("Load function", func() {
		var tmpFile *os.File

		BeforeEach(func() {
			var err error
			tmpFile, err = os.CreateTemp("", "config-test-*.yaml")
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			if tmpFile != nil {
				Expect(os.Remove(tmpFile.Name())).NotTo(HaveOccurred())
			}
		})

		Context("with valid single route config", func() {
			It("should load configuration successfully", func() {
				content := `routes:
- username: alice
  target:
    host: example.com
    port: 22
    user: alice
    insecure: true
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: alice-secret
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				config, err := Load(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
				Expect(config).NotTo(BeNil())
				Expect(config.Routes).To(HaveLen(1))
				Expect(config.Routes[0].Username).To(Equal("alice"))
				Expect(config.Routes[0].Target.Host).To(Equal("example.com"))
				Expect(config.Routes[0].Target.Port).To(Equal(22))
			})
		})

		Context("with target host_key and insecure fields", func() {
			It("should load host_key from config", func() {
				content := `routes:
- username: alice
  target:
    host: example.com
    port: 22
    user: alice
    host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: alice-secret
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				config, err := Load(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
				Expect(config.Routes[0].Target.HostKey).To(Equal("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"))
				Expect(config.Routes[0].Target.Insecure).To(BeFalse())
			})

			It("should load insecure flag from config", func() {
				content := `routes:
- username: alice
  target:
    host: example.com
    port: 22
    user: alice
    insecure: true
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: alice-secret
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				config, err := Load(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
				Expect(config.Routes[0].Target.Insecure).To(BeTrue())
				Expect(config.Routes[0].Target.HostKey).To(BeEmpty())
			})

			It("should fail validation when neither host_key nor insecure is set", func() {
				content := `routes:
- username: alice
  target:
    host: example.com
    port: 22
    user: alice
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: alice-secret
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				_, err = Load(tmpFile.Name())
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("must set either host_key or insecure: true"))
			})
		})

		Context("with multiple routes and different auth types", func() {
			It("should load all routes correctly", func() {
				content := `routes:
- username: alice
  target:
    host: alice.example.com
    port: 22
    user: alice
    insecure: true
    auth:
      type: password
      password: alice-secret
  auth:
  - type: password
    password: alice-password
- username: bob
  target:
    host: bob.example.com
    port: 2222
    user: bob
    insecure: true
    auth:
      type: key
      key_path: /path/to/key
  auth:
  - type: key
    authorized_keys:
    - ssh-rsa AAAA...
  - type: password_hash
    password_hash: $2a$10$...
    hash_type: bcrypt
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				config, err := Load(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
				Expect(config).NotTo(BeNil())
				Expect(config.Routes).To(HaveLen(2))

				// Verify alice route
				Expect(config.Routes[0].Username).To(Equal("alice"))
				Expect(config.Routes[0].Target.Host).To(Equal("alice.example.com"))
				Expect(config.Routes[0].Auth).To(HaveLen(1))
				Expect(config.Routes[0].Auth[0].Type).To(Equal("password"))

				// Verify bob route
				Expect(config.Routes[1].Username).To(Equal("bob"))
				Expect(config.Routes[1].Target.Host).To(Equal("bob.example.com"))
				Expect(config.Routes[1].Target.Port).To(Equal(2222))
				Expect(config.Routes[1].Auth).To(HaveLen(2))
				Expect(config.Routes[1].Auth[0].Type).To(Equal("key"))
				Expect(config.Routes[1].Auth[1].Type).To(Equal("password_hash"))
			})
		})

		Context("with invalid YAML syntax", func() {
			It("should return an error", func() {
				content := "invalid: yaml: content: ["
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				_, err = Load(tmpFile.Name())
				Expect(err).To(HaveOccurred())
			})
		})

		Context("with empty routes", func() {
			It("should load empty configuration", func() {
				content := "routes: []"
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				config, err := Load(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
				Expect(config).NotTo(BeNil())
				Expect(config.Routes).To(BeEmpty())
			})
		})

		Context("with missing routes field", func() {
			It("should load configuration with nil routes", func() {
				content := "other_field: value"
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				config, err := Load(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
				Expect(config).NotTo(BeNil())
				Expect(config.Routes).To(BeNil())
			})
		})

		Context("with non-existent file", func() {
			It("should return an error", func() {
				nonExistentFile := filepath.Join(os.TempDir(), "non-existent-config.yaml")
				_, err := Load(nonExistentFile)
				Expect(err).To(HaveOccurred())
			})
		})

		Context("with permission denied file", func() {
			It("should return an error", func() {
				if os.Getuid() == 0 {
					Skip("Skipping permission test when running as root")
				}

				content := "routes: []"
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				// Remove read permissions
				err = os.Chmod(tmpFile.Name(), 0000)
				Expect(err).NotTo(HaveOccurred())

				// Restore permissions for cleanup
				defer func() {
					_ = os.Chmod(tmpFile.Name(), 0644)
				}()

				_, err = Load(tmpFile.Name())
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("LoadWithData function", func() {
		var tmpFile *os.File

		BeforeEach(func() {
			var err error
			tmpFile, err = os.CreateTemp("", "config-test-*.yaml")
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			if tmpFile != nil {
				Expect(os.Remove(tmpFile.Name())).NotTo(HaveOccurred())
			}
		})

		It("should return both config and raw data", func() {
			content := `routes:
- username: test
  target:
    host: test.com
    port: 22
    user: test
    insecure: true
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: test-password
`
			_, err := tmpFile.WriteString(content)
			Expect(err).NotTo(HaveOccurred())
			Expect(tmpFile.Close()).NotTo(HaveOccurred())

			config, data, err := LoadWithData(tmpFile.Name())
			Expect(err).NotTo(HaveOccurred())
			Expect(config).NotTo(BeNil())
			Expect(data).NotTo(BeNil())
			Expect(string(data)).To(Equal(content))
			Expect(config.Routes).To(HaveLen(1))
			Expect(config.Routes[0].Username).To(Equal("test"))
		})

		Context("with non-existent file", func() {
			It("should return an error", func() {
				nonExistentFile := filepath.Join(os.TempDir(), "non-existent-config.yaml")
				_, _, err := LoadWithData(nonExistentFile)
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("ConfigManager", func() {
		var tmpFile *os.File

		BeforeEach(func() {
			var err error
			tmpFile, err = os.CreateTemp("", "config-test-*.yaml")
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			if tmpFile != nil {
				Expect(os.Remove(tmpFile.Name())).NotTo(HaveOccurred())
			}
		})

		Describe("NewConfigManager", func() {
			Context("with valid config file", func() {
				It("should create ConfigManager successfully", func() {
					content := `routes:
- username: alice
  target:
    host: example.com
    port: 22
    user: alice
    insecure: true
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: alice-secret
`
					_, err := tmpFile.WriteString(content)
					Expect(err).NotTo(HaveOccurred())
					Expect(tmpFile.Close()).NotTo(HaveOccurred())

					cm, err := NewConfigManager(tmpFile.Name())
					Expect(err).NotTo(HaveOccurred())
					Expect(cm).NotTo(BeNil())
					defer func() {
						Expect(cm.Close()).NotTo(HaveOccurred())
					}()

					Expect(cm.config).NotTo(BeNil())
					Expect(cm.config.Routes).To(HaveLen(1))

					// Check hash is set
					emptyHash := [32]byte{}
					Expect(cm.configHash).NotTo(Equal(emptyHash))
				})
			})

			Context("with non-existent file", func() {
				It("should return an error", func() {
					nonExistentFile := filepath.Join(os.TempDir(), "non-existent-config.yaml")
					_, err := NewConfigManager(nonExistentFile)
					Expect(err).To(HaveOccurred())
				})
			})
		})

		Describe("GetConfig", func() {
			var cm *ConfigManager

			BeforeEach(func() {
				content := `routes:
- username: alice
  target:
    host: example.com
    port: 22
    user: alice
    insecure: true
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: alice-secret
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				cm, err = NewConfigManager(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				if cm != nil {
					Expect(cm.Close()).NotTo(HaveOccurred())
				}
			})

			It("should return current configuration", func() {
				config := cm.GetConfig()
				Expect(config).NotTo(BeNil())
				Expect(config.Routes).To(HaveLen(1))
				Expect(config.Routes[0].Username).To(Equal("alice"))
			})
		})

		Describe("GetRouteMap", func() {
			var cm *ConfigManager

			BeforeEach(func() {
				content := `routes:
- username: alice
  target:
    host: alice.example.com
    port: 22
    user: alice
    insecure: true
    auth:
      type: password
      password: alice-secret
  auth:
  - type: password
    password: alice-password
- username: bob
  target:
    host: bob.example.com
    port: 22
    user: bob
    insecure: true
    auth:
      type: password
      password: bob-secret
  auth:
  - type: password
    password: bob-password
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				cm, err = NewConfigManager(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				if cm != nil {
					Expect(cm.Close()).NotTo(HaveOccurred())
				}
			})

			It("should return route map with all users", func() {
				routeMap := cm.GetRouteMap()
				Expect(routeMap).To(HaveLen(2))
				Expect(routeMap).To(HaveKey("alice"))
				Expect(routeMap).To(HaveKey("bob"))
				Expect(routeMap["alice"].Target.Host).To(Equal("alice.example.com"))
				Expect(routeMap["bob"].Target.Host).To(Equal("bob.example.com"))
			})

			Context("with concurrent access", func() {
				It("should handle multiple goroutines safely", func() {
					done := make(chan bool, 10)
					for i := 0; i < 10; i++ {
						go func(id int) {
							defer func() { done <- true }()

							for j := 0; j < 100; j++ {
								routeMap := cm.GetRouteMap()
								Expect(routeMap).To(HaveLen(2))
								Expect(routeMap).To(HaveKey("alice"))
								Expect(routeMap).To(HaveKey("bob"))
							}
						}(i)
					}

					// Wait for all goroutines to complete
					for i := 0; i < 10; i++ {
						<-done
					}
				})
			})
		})

		Describe("Configuration Reloading", func() {
			var cm *ConfigManager

			BeforeEach(func() {
				initialContent := `routes:
- username: alice
  target:
    host: alice.example.com
    port: 22
    user: alice
    insecure: true
    auth:
      type: password
      password: alice-secret
  auth:
  - type: password
    password: alice-password
`
				_, err := tmpFile.WriteString(initialContent)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				cm, err = NewConfigManager(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				if cm != nil {
					Expect(cm.Close()).NotTo(HaveOccurred())
				}
			})

			Context("when config file changes", func() {
				It("should reload configuration automatically", func() {
					// Verify initial config
					config := cm.GetConfig()
					Expect(config.Routes).To(HaveLen(1))

					// Update config file with new content
					updatedContent := `routes:
- username: alice
  target:
    host: alice.example.com
    port: 22
    user: alice
    insecure: true
    auth:
      type: password
      password: alice-secret
  auth:
  - type: password
    password: alice-password
- username: bob
  target:
    host: bob.example.com
    port: 22
    user: bob
    insecure: true
    auth:
      type: password
      password: bob-secret
  auth:
  - type: password
    password: bob-password
`
					err := os.WriteFile(tmpFile.Name(), []byte(updatedContent), 0644)
					Expect(err).NotTo(HaveOccurred())

					// Wait for config reload
					Eventually(func() int {
						return len(cm.GetConfig().Routes)
					}, "5s", "100ms").Should(Equal(2))

					routeMap := cm.GetRouteMap()
					Expect(routeMap).To(HaveLen(2))
					Expect(routeMap).To(HaveKey("alice"))
					Expect(routeMap).To(HaveKey("bob"))
				})
			})

			Context("when same content is written", func() {
				It("should not reload due to SHA256 optimization", func() {
					initialContent := `routes:
- username: alice
  target:
    host: alice.example.com
    port: 22
    user: alice
    insecure: true
    auth:
      type: password
      password: alice-secret
  auth:
  - type: password
    password: alice-password
`
					// Get initial hash
					initialHash := cm.configHash

					// Write the same content again
					err := os.WriteFile(tmpFile.Name(), []byte(initialContent), 0644)
					Expect(err).NotTo(HaveOccurred())

					// Wait a bit for file system events
					time.Sleep(200 * time.Millisecond)

					// Hash should remain the same
					Expect(cm.configHash).To(Equal(initialHash))

					// Verify routes are still the same
					config := cm.GetConfig()
					Expect(config.Routes).To(HaveLen(1))
				})
			})

			Context("when invalid config is written", func() {
				It("should keep original config after failed reload", func() {
					// Write invalid YAML to trigger reload error
					invalidContent := "invalid: yaml: content: ["
					err := os.WriteFile(tmpFile.Name(), []byte(invalidContent), 0644)
					Expect(err).NotTo(HaveOccurred())

					// Wait a bit for file system events
					time.Sleep(200 * time.Millisecond)

					// Original config should still be available
					config := cm.GetConfig()
					Expect(config.Routes).To(HaveLen(1))
				})
			})
		})

		Describe("Close", func() {
			var cm *ConfigManager

			BeforeEach(func() {
				content := `routes:
- username: alice
  target:
    host: alice.example.com
    port: 22
    user: alice
    insecure: true
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: alice-password
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				cm, err = NewConfigManager(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
			})

			It("should close without error", func() {
				err := cm.Close()
				Expect(err).NotTo(HaveOccurred())

				// Verify we can still get config after close (should not panic)
				config := cm.GetConfig()
				Expect(config).NotTo(BeNil())

				// Don't call Close again to avoid closing channel twice
			})
		})

		Describe("Edge cases", func() {
			Context("with empty routes", func() {
				It("should handle empty configuration", func() {
					content := `routes: []`
					_, err := tmpFile.WriteString(content)
					Expect(err).NotTo(HaveOccurred())
					Expect(tmpFile.Close()).NotTo(HaveOccurred())

					cm, err := NewConfigManager(tmpFile.Name())
					Expect(err).NotTo(HaveOccurred())
					defer func() {
						Expect(cm.Close()).NotTo(HaveOccurred())
					}()

					config := cm.GetConfig()
					Expect(config.Routes).To(BeEmpty())

					routeMap := cm.GetRouteMap()
					Expect(routeMap).To(BeEmpty())
				})
			})

			Context("with large configuration", func() {
				It("should handle 100 routes efficiently", func() {
					content := `routes:`
					for i := 0; i < 100; i++ {
						content += fmt.Sprintf(`
- username: user%d
  target:
    host: host%d.example.com
    port: 22
    user: user%d
    insecure: true
    auth:
      type: password
      password: secret%d
  auth:
  - type: password
    password: password%d
`, i, i, i, i, i)
					}

					_, err := tmpFile.WriteString(content)
					Expect(err).NotTo(HaveOccurred())
					Expect(tmpFile.Close()).NotTo(HaveOccurred())

					cm, err := NewConfigManager(tmpFile.Name())
					Expect(err).NotTo(HaveOccurred())
					defer func() {
						Expect(cm.Close()).NotTo(HaveOccurred())
					}()

					config := cm.GetConfig()
					Expect(config.Routes).To(HaveLen(100))

					routeMap := cm.GetRouteMap()
					Expect(routeMap).To(HaveLen(100))

					// Test specific user lookup
					Expect(routeMap).To(HaveKey("user50"))
					Expect(routeMap["user50"].Target.Host).To(Equal("host50.example.com"))
				})
			})
		})
	})

	Describe("Config Structs", func() {
		Context("Config struct", func() {
			It("should handle empty configuration", func() {
				config := &Config{}
				Expect(config.Routes).To(BeNil())
				Expect(len(config.Routes)).To(Equal(0))
			})
		})

		Context("Route struct", func() {
			It("should support multiple auth methods", func() {
				route := Route{
					Username: "test",
					Auth: []AuthMethod{
						{Type: "password", Password: "secret"},
						{Type: "key", AuthorizedKeys: []string{"ssh-rsa AAA..."}},
						{Type: "password_hash", PasswordHash: "$2a$10$...", HashType: "bcrypt"},
					},
				}

				Expect(route.Auth).To(HaveLen(3))
				Expect(route.Auth[0].Type).To(Equal("password"))
				Expect(route.Auth[1].Type).To(Equal("key"))
				Expect(route.Auth[2].Type).To(Equal("password_hash"))
			})

			It("should support usernameRegex field", func() {
				route := Route{
					UsernameRegex: `^(?P<env>dev|prod)-(?P<service>.+)$`,
					Auth: []AuthMethod{
						{Type: "password", Password: "secret"},
					},
				}
				Expect(route.UsernameRegex).To(Equal(`^(?P<env>dev|prod)-(?P<service>.+)$`))
			})
		})

		Context("TargetAuth struct", func() {
			It("should support different auth types", func() {
				authTypes := []struct {
					name     string
					auth     TargetAuth
					expected string
				}{
					{"password auth", TargetAuth{Type: "password", Password: "secret"}, "password"},
					{"key auth", TargetAuth{Type: "key", KeyPath: "/path/to/key"}, "key"},
					{"password_hash auth", TargetAuth{Type: "password_hash"}, "password_hash"},
				}

				for _, authType := range authTypes {
					Expect(authType.auth.Type).To(Equal(authType.expected))
				}
			})
		})

		Context("Target struct", func() {
			It("should support host_key field", func() {
				target := Target{
					Host:    "example.com",
					Port:    22,
					User:    "deploy",
					HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest...",
				}
				Expect(target.HostKey).To(Equal("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest..."))
				Expect(target.Insecure).To(BeFalse())
			})

			It("should support insecure field", func() {
				target := Target{
					Host:     "example.com",
					Port:     22,
					User:     "deploy",
					Insecure: true,
				}
				Expect(target.Insecure).To(BeTrue())
				Expect(target.HostKey).To(BeEmpty())
			})
		})
	})

	Describe("UsernameRegex and FindRoute", func() {
		var tmpFile *os.File

		BeforeEach(func() {
			var err error
			tmpFile, err = os.CreateTemp("", "config-regex-test-*.yaml")
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			if tmpFile != nil {
				Expect(os.Remove(tmpFile.Name())).NotTo(HaveOccurred())
			}
		})

		Context("loading config with usernameRegex", func() {
			It("should compile regex patterns on load", func() {
				content := `routes:
- usernameRegex: "^(?P<env>dev|prod)-(?P<service>.+)$"
  target:
    host: "{{.Named.env}}-{{.Named.service}}.internal"
    port: 22
    user: deploy
    insecure: true
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: my-secret
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				config, err := Load(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
				Expect(config.Routes).To(HaveLen(1))
				Expect(config.Routes[0].UsernameRegex).To(Equal(`^(?P<env>dev|prod)-(?P<service>.+)$`))
			})

			It("should fail on invalid regex", func() {
				content := `routes:
- usernameRegex: "[invalid"
  target:
    host: example.com
    port: 22
    user: test
    insecure: true
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: test
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				_, err = Load(tmpFile.Name())
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to compile usernameRegex"))
			})
		})

		Context("FindRoute with exact username", func() {
			It("should match exact username routes", func() {
				content := `routes:
- username: alice
  target:
    host: alice.example.com
    port: 22
    user: alice
    insecure: true
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: alice-password
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				cm, err := NewConfigManager(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					Expect(cm.Close()).NotTo(HaveOccurred())
				}()

				match := cm.FindRoute("alice")
				Expect(match).NotTo(BeNil())
				Expect(match.Route.Username).To(Equal("alice"))
				Expect(match.Groups).To(BeNil())
				Expect(match.Named).To(BeNil())
			})

			It("should return nil for non-matching username", func() {
				content := `routes:
- username: alice
  target:
    host: alice.example.com
    port: 22
    user: alice
    insecure: true
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: alice-password
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				cm, err := NewConfigManager(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					Expect(cm.Close()).NotTo(HaveOccurred())
				}()

				match := cm.FindRoute("bob")
				Expect(match).To(BeNil())
			})
		})

		Context("FindRoute with usernameRegex", func() {
			It("should match regex routes with named groups", func() {
				content := `routes:
- usernameRegex: "^(?P<env>dev|staging|prod)-(?P<service>.+)$"
  target:
    host: "{{.Named.env}}-{{.Named.service}}.internal"
    port: 22
    user: deploy
    insecure: true
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: my-password
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				cm, err := NewConfigManager(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					Expect(cm.Close()).NotTo(HaveOccurred())
				}()

				match := cm.FindRoute("dev-myapp")
				Expect(match).NotTo(BeNil())
				Expect(match.Groups).To(HaveLen(3)) // full match + 2 groups
				Expect(match.Groups[0]).To(Equal("dev-myapp"))
				Expect(match.Groups[1]).To(Equal("dev"))
				Expect(match.Groups[2]).To(Equal("myapp"))
				Expect(match.Named).To(HaveKeyWithValue("env", "dev"))
				Expect(match.Named).To(HaveKeyWithValue("service", "myapp"))

				match2 := cm.FindRoute("prod-backend")
				Expect(match2).NotTo(BeNil())
				Expect(match2.Named).To(HaveKeyWithValue("env", "prod"))
				Expect(match2.Named).To(HaveKeyWithValue("service", "backend"))
			})

			It("should match regex with positional groups (no named groups)", func() {
				content := `routes:
- usernameRegex: "^(dev|prod)-(.+)$"
  target:
    host: "{{index .Groups 1}}-{{index .Groups 2}}.internal"
    port: 22
    user: deploy
    insecure: true
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: my-password
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				cm, err := NewConfigManager(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					Expect(cm.Close()).NotTo(HaveOccurred())
				}()

				match := cm.FindRoute("dev-frontend")
				Expect(match).NotTo(BeNil())
				Expect(match.Groups).To(HaveLen(3))
				Expect(match.Groups[0]).To(Equal("dev-frontend"))
				Expect(match.Groups[1]).To(Equal("dev"))
				Expect(match.Groups[2]).To(Equal("frontend"))
				Expect(match.Named).To(BeEmpty())
			})

			It("should not match if regex does not match", func() {
				content := `routes:
- usernameRegex: "^(?P<env>dev|prod)-(?P<service>.+)$"
  target:
    host: example.com
    port: 22
    user: deploy
    insecure: true
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: my-password
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				cm, err := NewConfigManager(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					Expect(cm.Close()).NotTo(HaveOccurred())
				}()

				match := cm.FindRoute("nope-nope")
				Expect(match).To(BeNil())
			})

			It("should prefer exact match over regex match", func() {
				content := `routes:
- username: dev-myapp
  target:
    host: exact-host.internal
    port: 22
    user: deploy
    insecure: true
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: my-password
- usernameRegex: "^(?P<env>dev|prod)-(?P<service>.+)$"
  target:
    host: "{{.Named.env}}-{{.Named.service}}.internal"
    port: 22
    user: deploy
    insecure: true
    auth:
      type: password
      password: secret
  auth:
  - type: password
    password: my-password
`
				_, err := tmpFile.WriteString(content)
				Expect(err).NotTo(HaveOccurred())
				Expect(tmpFile.Close()).NotTo(HaveOccurred())

				cm, err := NewConfigManager(tmpFile.Name())
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					Expect(cm.Close()).NotTo(HaveOccurred())
				}()

				// Exact match should win
				match := cm.FindRoute("dev-myapp")
				Expect(match).NotTo(BeNil())
				Expect(match.Route.Username).To(Equal("dev-myapp"))
				Expect(match.Route.Target.Host).To(Equal("exact-host.internal"))
				Expect(match.Groups).To(BeNil())

				// Regex match should work for non-exact
				match2 := cm.FindRoute("prod-myapp")
				Expect(match2).NotTo(BeNil())
				Expect(match2.Named).To(HaveKeyWithValue("env", "prod"))
			})
		})
	})

	Describe("ResolveHost", func() {
		Context("with static host (no template)", func() {
			It("should return the host as-is", func() {
				match := &RouteMatch{
					Route:  &Route{},
					Groups: nil,
					Named:  nil,
				}
				host, err := ResolveHost("example.com", match, "alice")
				Expect(err).NotTo(HaveOccurred())
				Expect(host).To(Equal("example.com"))
			})
		})

		Context("with Go template using named groups", func() {
			It("should resolve template with named groups", func() {
				match := &RouteMatch{
					Route:  &Route{},
					Groups: []string{"dev-myapp", "dev", "myapp"},
					Named:  map[string]string{"env": "dev", "service": "myapp"},
				}
				host, err := ResolveHost("{{.Named.env}}-{{.Named.service}}.internal", match, "dev-myapp")
				Expect(err).NotTo(HaveOccurred())
				Expect(host).To(Equal("dev-myapp.internal"))
			})
		})

		Context("with Go template using positional groups", func() {
			It("should resolve template with index function", func() {
				match := &RouteMatch{
					Route:  &Route{},
					Groups: []string{"dev-myapp", "dev", "myapp"},
					Named:  map[string]string{},
				}
				host, err := ResolveHost("{{index .Groups 1}}.{{index .Groups 2}}.internal", match, "dev-myapp")
				Expect(err).NotTo(HaveOccurred())
				Expect(host).To(Equal("dev.myapp.internal"))
			})
		})

		Context("with Go template using Username", func() {
			It("should resolve template with username", func() {
				match := &RouteMatch{
					Route:  &Route{},
					Groups: nil,
					Named:  nil,
				}
				host, err := ResolveHost("{{.Username}}.internal", match, "alice")
				Expect(err).NotTo(HaveOccurred())
				Expect(host).To(Equal("alice.internal"))
			})
		})

		Context("with invalid template", func() {
			It("should return an error", func() {
				match := &RouteMatch{
					Route:  &Route{},
					Groups: nil,
					Named:  nil,
				}
				_, err := ResolveHost("{{.Invalid", match, "alice")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to parse host template"))
			})
		})

		Context("with template resolving to empty string", func() {
			It("should return an error", func() {
				match := &RouteMatch{
					Route:  &Route{},
					Groups: nil,
					Named:  map[string]string{},
				}
				_, err := ResolveHost("{{if .Named.nonexistent}}{{.Named.nonexistent}}{{end}}", match, "alice")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("resolved to empty string"))
			})
		})
	})
})
