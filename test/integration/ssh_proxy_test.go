package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/schrodit/ssh-proxy/pkg/config"
	"golang.org/x/crypto/ssh"
)

var _ = Describe("SSH Proxy Integration Tests", func() {
	var (
		dockerComposeFile string
		testConfigFile    string
		ctx               context.Context
		cancel            context.CancelFunc
	)

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())

		wd, err := os.Getwd()
		Expect(err).NotTo(HaveOccurred())

		projectRoot := filepath.Join(wd, "..", "..")
		dockerComposeFile = filepath.Join(projectRoot, "docker-compose.yml")
		testConfigFile = filepath.Join(projectRoot, "test", "test-config.yaml")

		// Verify files exist
		_, err = os.Stat(dockerComposeFile)
		Expect(err).NotTo(HaveOccurred(), "docker-compose.yml should exist")
		_, err = os.Stat(testConfigFile)
		Expect(err).NotTo(HaveOccurred(), "test-config.yaml should exist")
	})

	AfterEach(func() {
		By("Cancel context")
		if cancel != nil {
			cancel()
		}
	})

	Describe("Docker Environment", func() {
		BeforeEach(func() {
			By("Starting Docker Compose environment")
			cmd := exec.CommandContext(ctx, "docker", "compose", "-f", dockerComposeFile, "up", "-d")
			cmd.Dir = filepath.Dir(dockerComposeFile)
			output, err := cmd.CombinedOutput()
			if err != nil {
				Fail(fmt.Sprintf("Failed to start docker environment: %v\nOutput: %s", err, output))
			}

			By("Waiting for services to be ready")
			time.Sleep(15 * time.Second)

			By("Verifying SSH proxy is listening")
			Eventually(func() error {
				conn, err := net.DialTimeout("tcp", "localhost:2222", 5*time.Second)
				if err != nil {
					return err
				}
				if err := conn.Close(); err != nil {
					return err
				}
				return nil
			}, "30s", "2s").Should(Succeed(), "SSH proxy should be listening on port 2222")
		})

		AfterEach(func() {
			By("Querying and outputting SSH proxy logs")
			logCmd := exec.CommandContext(ctx, "docker", "compose", "-f", dockerComposeFile, "logs", "ssh-proxy")
			logCmd.Dir = filepath.Dir(dockerComposeFile)
			logOutput, logErr := logCmd.CombinedOutput()
			if logErr != nil {
				GinkgoWriter.Printf("Warning: Failed to get ssh-proxy logs: %v\n", logErr)
			} else {
				GinkgoWriter.Printf("SSH Proxy Logs:\n%s\n", string(logOutput))
			}

			By("Stopping Docker Compose environment")
			cmd := exec.CommandContext(ctx, "docker", "compose", "-f", dockerComposeFile, "down")
			cmd.Dir = filepath.Dir(dockerComposeFile)
			output, err := cmd.CombinedOutput()
			if err != nil {
				GinkgoWriter.Printf("Warning: Failed to stop docker environment: %v\nOutput: %s\n", err, output)
			}
		})

		Context("SSH Connection Tests", func() {
			testSSHConnection := func(username, password, expectedHostname string) {
				It(fmt.Sprintf("should successfully connect user %s and route to %s", username, expectedHostname), func() {
					config := &ssh.ClientConfig{
						User: username,
						Auth: []ssh.AuthMethod{
							ssh.Password(password),
						},
						HostKeyCallback: ssh.InsecureIgnoreHostKey(),
						Timeout:         10 * time.Second,
					}

					By(fmt.Sprintf("Establishing SSH connection for user %s", username))
					client, err := ssh.Dial("tcp", "localhost:2222", config)
					Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Should be able to connect as %s", username))
					defer func() {
						if err := client.Close(); err != nil {
							GinkgoWriter.Printf("Warning: Failed to close SSH client: %v\n", err)
						}
					}()

					By("Running hostname command on the target server")
					session, err := client.NewSession()
					Expect(err).NotTo(HaveOccurred())
					defer func() {
						if err := session.Close(); err != nil {
							GinkgoWriter.Printf("Warning: Failed to close SSH session: %v\n", err)
						}
					}()

					output, err := session.Output("hostname")
					Expect(err).NotTo(HaveOccurred(), "Should be able to run hostname command")

					hostname := string(output)
					By(fmt.Sprintf("Verifying hostname contains '%s', got: %s", expectedHostname, hostname))
					Expect(hostname).To(ContainSubstring(expectedHostname),
						fmt.Sprintf("Expected hostname to contain '%s', but got '%s'", expectedHostname, hostname))
				})
			}

			testSSHConnection("alice", "alice-secret", "alice")
			testSSHConnection("bob", "bob-secret", "bob")
			testSSHConnection("charlie", "charlie-secret", "alice")

			It("should fail authentication with wrong password", func() {
				config := &ssh.ClientConfig{
					User: "alice",
					Auth: []ssh.AuthMethod{
						ssh.Password("wrong-password"),
					},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         10 * time.Second,
				}

				By("Attempting connection with wrong password")
				_, err := ssh.Dial("tcp", "localhost:2222", config)
				Expect(err).To(HaveOccurred(), "Should fail with wrong password")
			})

			It("should fail authentication with non-existent user", func() {
				config := &ssh.ClientConfig{
					User: "nonexistent",
					Auth: []ssh.AuthMethod{
						ssh.Password("any-password"),
					},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         10 * time.Second,
				}

				By("Attempting connection with non-existent user")
				_, err := ssh.Dial("tcp", "localhost:2222", config)
				Expect(err).To(HaveOccurred(), "Should fail with non-existent user")
			})

			It("should successfully authenticate using SSH key (ed25519)", func() {
				By("Loading private key from file")
				wd, err := os.Getwd()
				Expect(err).NotTo(HaveOccurred())
				keyPath := filepath.Join(wd, "..", "..", "test", "id_ed25519")

				keyBytes, err := os.ReadFile(keyPath)
				Expect(err).NotTo(HaveOccurred(), "Should be able to read private key file")

				signer, err := ssh.ParsePrivateKey(keyBytes)
				Expect(err).NotTo(HaveOccurred(), "Should be able to parse private key")

				config := &ssh.ClientConfig{
					User: "charlie",
					Auth: []ssh.AuthMethod{
						ssh.PublicKeys(signer),
					},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         10 * time.Second,
				}

				By("Establishing SSH connection using key authentication")
				client, err := ssh.Dial("tcp", "localhost:2222", config)
				Expect(err).NotTo(HaveOccurred(), "Should be able to connect using SSH key")
				defer func() {
					if err := client.Close(); err != nil {
						GinkgoWriter.Printf("Warning: Failed to close SSH client: %v\n", err)
					}
				}()

				By("Running hostname command on the target server")
				session, err := client.NewSession()
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					if err := session.Close(); err != nil {
						GinkgoWriter.Printf("Warning: Failed to close SSH session: %v\n", err)
					}
				}()

				output, err := session.Output("hostname")
				Expect(err).NotTo(HaveOccurred(), "Should be able to run hostname command")

				hostname := string(output)
				By(fmt.Sprintf("Verifying hostname contains 'alice' (charlie routes to alice), got: %s", hostname))
				Expect(hostname).To(ContainSubstring("alice"),
					fmt.Sprintf("Expected hostname to contain 'alice', but got '%s'", hostname))
			})

			It("should fail SSH key authentication with wrong key", func() {
				By("Generating a temporary wrong key")
				wrongSigner, err := generateTemporaryKey()
				Expect(err).NotTo(HaveOccurred(), "Should be able to generate temporary key")

				config := &ssh.ClientConfig{
					User: "charlie",
					Auth: []ssh.AuthMethod{
						ssh.PublicKeys(wrongSigner),
					},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         10 * time.Second,
				}

				By("Attempting connection with wrong SSH key")
				_, err = ssh.Dial("tcp", "localhost:2222", config)
				Expect(err).To(HaveOccurred(), "Should fail with wrong SSH key")
			})
		})

		Context("Multiple Session Tests", func() {
			It("should handle multiple concurrent connections", func() {
				config := &ssh.ClientConfig{
					User: "alice",
					Auth: []ssh.AuthMethod{
						ssh.Password("alice-secret"),
					},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         10 * time.Second,
				}

				By("Creating multiple concurrent SSH connections")
				var clients []*ssh.Client
				defer func() {
					for _, client := range clients {
						if client != nil {
							if err := client.Close(); err != nil {
								GinkgoWriter.Printf("Warning: Failed to close SSH client: %v\n", err)
							}
						}
					}
				}()

				// Create 3 concurrent connections
				for i := 0; i < 3; i++ {
					client, err := ssh.Dial("tcp", "localhost:2222", config)
					Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Connection %d should succeed", i+1))
					clients = append(clients, client)
				}

				By("Running commands on all connections")
				for i, client := range clients {
					session, err := client.NewSession()
					Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Session creation %d should succeed", i+1))

					output, err := session.Output("echo 'test'")
					Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Command execution %d should succeed", i+1))
					Expect(string(output)).To(ContainSubstring("test"), fmt.Sprintf("Command output %d should be correct", i+1))

					if err := session.Close(); err != nil {
						GinkgoWriter.Printf("Warning: Failed to close session %d: %v\n", i+1, err)
					}
				}
			})
		})

		Context("SSH Port Forwarding Tests", func() {
			It("should successfully establish local port forwarding using Go SSH client", func() {
				config := &ssh.ClientConfig{
					User: "alice",
					Auth: []ssh.AuthMethod{
						ssh.Password("alice-secret"),
					},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         10 * time.Second,
				}

				By("Establishing SSH connection")
				client, err := ssh.Dial("tcp", "localhost:2222", config)
				Expect(err).NotTo(HaveOccurred(), "Should be able to connect via SSH")
				defer func() {
					if err := client.Close(); err != nil {
						GinkgoWriter.Printf("Warning: Failed to close SSH client: %v\n", err)
					}
				}()

				By("Starting a simple HTTP server on the remote host")
				session, err := client.NewSession()
				Expect(err).NotTo(HaveOccurred())

				// Start a simple Python HTTP server on port 8080 in background
				err = session.Start("python3 -m http.server 8080 > /dev/null 2>&1 &")
				Expect(err).NotTo(HaveOccurred(), "Should be able to start HTTP server")
				Expect(session.Close()).NotTo(HaveOccurred())

				// Give the server time to start
				time.Sleep(2 * time.Second)

				By("Setting up local port forwarding")
				localPort := "18080"
				remotePort := "8080"

				listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%s", localPort))
				Expect(err).NotTo(HaveOccurred(), "Should be able to create local listener")
				defer func() { _ = listener.Close() }()

				// Handle port forwarding in a goroutine
				go func() {
					defer GinkgoRecover()
					for {
						select {
						case <-ctx.Done():
							return
						default:
							localConn, err := listener.Accept()
							if err != nil {
								if ctx.Err() != nil {
									return // Context cancelled
								}
								GinkgoWriter.Printf("Warning: Failed to accept local connection: %v\n", err)
								return
							}

							go func(localConn net.Conn) {
								defer GinkgoRecover()
								defer func() { _ = localConn.Close() }()

								remoteConn, err := client.Dial("tcp", fmt.Sprintf("localhost:%s", remotePort))
								if err != nil {
									GinkgoWriter.Printf("Warning: Failed to dial remote: %v\n", err)
									return
								}
								defer func() { _ = remoteConn.Close() }()
								go func() {
									defer GinkgoRecover()
									_, err := io.Copy(localConn, remoteConn)
									if err != nil {
										GinkgoWriter.Printf("Debug: Copy from remote to local ended: %v\n", err)
									}
								}()

								_, err = io.Copy(remoteConn, localConn)
								if err != nil {
									GinkgoWriter.Printf("Debug: Copy from local to remote ended: %v\n", err)
								}
							}(localConn)
						}
					}
				}()

				By("Testing the port forwarding connection")
				Eventually(func() error {
					conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%s", localPort), 2*time.Second)
					if err != nil {
						return err
					}
					defer func() { _ = conn.Close() }()

					// Send a simple HTTP GET request
					_, err = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
					if err != nil {
						return err
					}

					// Read response to verify server is responding
					buffer := make([]byte, 1024)
					n, err := conn.Read(buffer)
					if err != nil {
						return err
					}

					response := string(buffer[:n])
					if !strings.Contains(response, "HTTP/") {
						return fmt.Errorf("unexpected response: %s", response)
					}

					return nil
				}, "10s", "1s").Should(Succeed(), "Should be able to connect through port forwarding")

				By("Cleaning up the HTTP server")
				cleanupSession, err := client.NewSession()
				if err == nil {
					Expect(cleanupSession.Run("pkill -f 'python3 -m http.server'")).NotTo(HaveOccurred())
					if err := cleanupSession.Close(); err != nil {
						GinkgoWriter.Printf("Warning: Failed to close cleanup session: %v\n", err)
					}
				}
			})

			It("should successfully establish local port forwarding using OpenSSH client", func() {
				checkSshpassAvailable()

				By("Setting up local port forwarding using OpenSSH client")

				// Get absolute path to ssh_config
				wd, err := os.Getwd()
				Expect(err).NotTo(HaveOccurred())
				projectRoot := filepath.Join(wd, "..")
				sshConfigPath := filepath.Join(projectRoot, "ssh_config")

				// Verify ssh_config exists
				_, err = os.Stat(sshConfigPath)
				Expect(err).NotTo(HaveOccurred(), "ssh_config should exist")

				localPort := "18081"
				remotePort := "8080"

				// Start SSH with port forwarding in background
				sshCmd := exec.CommandContext(ctx, "sshpass", "-p", "alice-secret", "ssh",
					"-F", sshConfigPath,
					"-L", fmt.Sprintf("%s:localhost:%s", localPort, remotePort),
					"-N", // Don't execute remote commands
					"alice-proxy")
				sshCmd.Env = append(os.Environ(), "SSH_AUTH_SOCK=") // Disable SSH agent

				err = sshCmd.Start()
				Expect(err).NotTo(HaveOccurred(), "SSH port forwarding should start successfully")

				defer func() {
					if sshCmd.Process != nil {
						Expect(sshCmd.Process.Kill()).NotTo(HaveOccurred())
						Expect(sshCmd.Wait()).NotTo(HaveOccurred())
					}
				}()

				// Give SSH time to establish the tunnel
				time.Sleep(3 * time.Second)

				By("Starting HTTP server on remote host")
				serverCmd := exec.CommandContext(ctx, "sshpass", "-p", "alice-secret", "ssh",
					"-F", sshConfigPath,
					"alice-proxy",
					"python3 -m http.server 8080 > /dev/null 2>&1 &")
				serverCmd.Env = append(os.Environ(), "SSH_AUTH_SOCK=") // Disable SSH agent

				serverOutput, err := serverCmd.CombinedOutput()
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Should start HTTP server. Output: %s", serverOutput))

				// Give the server time to start
				time.Sleep(2 * time.Second)

				By("Testing the port forwarding connection")
				Eventually(func() error {
					conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%s", localPort), 2*time.Second)
					if err != nil {
						return err
					}
					defer func() {
						Expect(conn.Close()).NotTo(HaveOccurred())
					}()

					// Send a simple HTTP GET request
					_, err = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
					if err != nil {
						return err
					}

					// Read response to verify server is responding
					buffer := make([]byte, 1024)
					n, err := conn.Read(buffer)
					if err != nil {
						return err
					}

					response := string(buffer[:n])
					if !strings.Contains(response, "HTTP/") {
						return fmt.Errorf("unexpected response: %s", response)
					}

					return nil
				}, "15s", "1s").Should(Succeed(), "Should be able to connect through port forwarding")

				By("Cleaning up the HTTP server")
				cleanupCmd := exec.CommandContext(ctx, "sshpass", "-p", "alice-secret", "ssh",
					"-F", sshConfigPath,
					"alice-proxy",
					"pkill -f 'python3 -m http.server' || true")
				cleanupCmd.Env = append(os.Environ(), "SSH_AUTH_SOCK=")
				Expect(cleanupCmd.Run()).NotTo(HaveOccurred())
			})
		})

		Context("Configuration Reload Tests", func() {
			It("should reload configuration when config file changes", func() {
				By("Creating a temporary config file")

				tempConfig := `routes:
- username: testuser
  target:
    host: localhost
    port: 22
    user: testuser
    auth:
      type: password
      password: testuser-secret
  auth:
  - type: password
    password: testuser-password
`

				tempFile, err := os.CreateTemp("", "test-config-*.yaml")
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					Expect(os.Remove(tempFile.Name())).NotTo(HaveOccurred())
				}()

				_, err = tempFile.WriteString(tempConfig)
				Expect(err).NotTo(HaveOccurred())
				Expect(tempFile.Close()).NotTo(HaveOccurred())

				By("Creating a ConfigManager")
				configManager, err := config.NewConfigManager(tempFile.Name())
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					Expect(configManager.Close()).NotTo(HaveOccurred())
				}()

				By("Verifying initial config")
				initialConfig := configManager.GetConfig()
				Expect(len(initialConfig.Routes)).To(Equal(1))
				Expect(initialConfig.Routes[0].Username).To(Equal("testuser"))

				By("Testing concurrent access to route map")
				for i := 0; i < 5; i++ {
					routeMap := configManager.GetRouteMap()
					Expect(len(routeMap)).To(Equal(1))
					Expect(routeMap["testuser"]).NotTo(BeNil())
				}

				By("Modifying the config file")
				newConfig := `routes:
- username: testuser
  target:
    host: localhost
    port: 22
    user: testuser
    auth:
      type: password
      password: testuser-secret
  auth:
  - type: password
    password: testuser-password
- username: newuser
  target:
    host: localhost
    port: 22
    user: newuser
    auth:
      type: password
      password: newuser-secret
  auth:
  - type: password
    password: newuser-password
`

				err = os.WriteFile(tempFile.Name(), []byte(newConfig), 0644)
				Expect(err).NotTo(HaveOccurred())

				By("Waiting for config update notification")
				Eventually(func() int {
					return len(configManager.GetConfig().Routes)
				}, "5s", "100ms").Should(Equal(2), "Config should be reloaded with 2 routes")

				By("Verifying the updated config")
				updatedConfig := configManager.GetConfig()
				Expect(len(updatedConfig.Routes)).To(Equal(2))

				routeMap := configManager.GetRouteMap()
				Expect(len(routeMap)).To(Equal(2))
				Expect(routeMap["testuser"]).NotTo(BeNil())
				Expect(routeMap["newuser"]).NotTo(BeNil())

				By("Testing concurrent access after config update")
				for i := 0; i < 5; i++ {
					routeMap := configManager.GetRouteMap()
					Expect(len(routeMap)).To(Equal(2))
				}
			})
		})

		Context("OpenSSH Client Tests", func() {
			testSSHCommand := func(sshHost, password, description string) {
				It(description, func() {
					checkSshpassAvailable()
					By(fmt.Sprintf("Running SSH command using OpenSSH client for %s", sshHost))
					expectedOutput := "integration-test-success"

					// Get absolute path to ssh_config
					wd, err := os.Getwd()
					Expect(err).NotTo(HaveOccurred())
					projectRoot := filepath.Join(wd, "..")
					sshConfigPath := filepath.Join(projectRoot, "ssh_config")

					// Verify ssh_config exists
					_, err = os.Stat(sshConfigPath)
					Expect(err).NotTo(HaveOccurred(), "ssh_config should exist")

					// Run SSH command using OpenSSH client
					cmd := exec.CommandContext(ctx, "sshpass", "-p", password, "ssh", "-F", sshConfigPath, sshHost, "echo", expectedOutput)
					cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK=") // Disable SSH agent

					output, err := cmd.CombinedOutput()
					Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("SSH command should succeed. Output: %s", output))

					By(fmt.Sprintf("Verifying command output contains '%s'", expectedOutput))
					outputStr := string(output)
					Expect(outputStr).To(ContainSubstring(expectedOutput),
						fmt.Sprintf("Expected output to contain '%s', but got '%s'", expectedOutput, outputStr))
				})
			}

			testSSHCommand("alice-proxy", "alice-secret", "should successfully connect to alice via SSH proxy using sshpass + OpenSSH client")
			testSSHCommand("bob-proxy", "bob-secret", "should successfully connect to bob via SSH proxy using sshpass + OpenSSH client")
			testSSHCommand("charlie-proxy", "charlie-secret", "should successfully connect to charlie via SSH proxy using sshpass + OpenSSH client")

			It("should successfully connect using SSH key authentication with OpenSSH client", func() {
				By("Running SSH command using OpenSSH client with key authentication")

				// Get absolute paths
				wd, err := os.Getwd()
				Expect(err).NotTo(HaveOccurred())
				projectRoot := filepath.Join(wd, "..", "..")
				sshConfigPath := filepath.Join(projectRoot, "test", "ssh_config")
				keyPath := filepath.Join(projectRoot, "test", "id_ed25519")

				// Verify files exist
				_, err = os.Stat(sshConfigPath)
				Expect(err).NotTo(HaveOccurred(), "ssh_config should exist")
				_, err = os.Stat(keyPath)
				Expect(err).NotTo(HaveOccurred(), "SSH key should exist")
				Expect(os.Chmod(keyPath, 0600)).NotTo(HaveOccurred())

				// Run SSH command with explicit key authentication
				cmd := exec.CommandContext(ctx, "ssh",
					"-F", sshConfigPath,
					"-i", keyPath,
					"-o", "PreferredAuthentications=publickey",
					"-o", "PubkeyAuthentication=yes",
					"-o", "PasswordAuthentication=no",
					"charlie-proxy",
					"hostname")
				cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK=") // Disable SSH agent

				output, err := cmd.CombinedOutput()
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("SSH key authentication should succeed. Output: %s", output))

				By("Verifying the command was executed on the target server")
				outputStr := string(output)
				Expect(outputStr).To(ContainSubstring("alice"),
					fmt.Sprintf("Expected hostname to contain 'alice' (charlie routes to alice), but got '%s'", outputStr))
			})

			It("should support interactive commands using OpenSSH client", func() {
				By("Running an interactive command sequence using sshpass")

				checkSshpassAvailable()

				wd, err := os.Getwd()
				Expect(err).NotTo(HaveOccurred())
				projectRoot := filepath.Join(wd, "..")
				sshConfigPath := filepath.Join(projectRoot, "ssh_config")

				// Create a simple script that we'll execute remotely
				scriptCommands := "pwd && whoami && echo 'Current directory and user info'"

				cmd := exec.CommandContext(ctx, "sshpass", "-p", "alice-secret", "ssh",
					"-F", sshConfigPath,
					"-o", "PreferredAuthentications=password",
					"-o", "PubkeyAuthentication=no",
					"alice-proxy", "/bin/sh", "-c", scriptCommands)
				cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK=") // Disable SSH agent

				output, err := cmd.CombinedOutput()
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Interactive SSH command should succeed. Output: %s", output))

				By("Verifying the script executed correctly")
				outputStr := string(output)
				Expect(outputStr).To(ContainSubstring("alice"), "Output should contain username 'alice'")
				Expect(outputStr).To(ContainSubstring("Current directory and user info"), "Output should contain our echo message")
			})
		})
	})
})

func checkSshpassAvailable() {
	_, err := exec.LookPath("sshpass")
	if err != nil {
		Skip("sshpass not found - skipping password-based interactive SSH test. Install with: apt-get install sshpass / brew install sshpass")
	}
}

// generateTemporaryKey creates a temporary SSH key pair for testing wrong key scenarios
func generateTemporaryKey() (ssh.Signer, error) {
	// Generate a new ed25519 key pair for testing
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Convert to SSH signer
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, err
	}

	return signer, nil
}
