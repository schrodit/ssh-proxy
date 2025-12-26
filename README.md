# SSH Proxy Server

A Go-based SSH proxy server that routes connections to different SSH targets based on the authenticated username.

## Features

- **Username-based routing**: Route SSH connections to different target servers based on the connecting username
- **Multiple authentication methods**: Support for both password and public key authentication
- **Automatic host key generation**: Generates host keys automatically if not provided

## Planned Features
- **Improve security**
  - Proper host key validation
  - Do not store passwords in plain text
- **Helm Chart**: Add a helm chart deployment
- **Full SSH protocol support**: Proxy all SSH features including channels, port forwarding, and file transfers
  - including tests for all features
- **Dynamic Routes**: Make it possible to dynamically add, remove, update routes
  - Would be preferrable to be a hot reload
  - first step would be a file realoder
  - build on top is a HTTP API to adjust routes
- **HA Deployment**: Deploy multiple replicas
  - Including a centralized routing table
  - Sessions that are moved.
- **Custom authentication**: Implement custom authentication logic per user
  - helpful if jwt or other custom auth should be used.
- **Dynamic host information resolver**: Dynmically/custom resolve host information like hostname, user, authentication.
- **Regex-based routing**: Support regex based routing
  - To be really useful this feature also needs some custom resolver where the host is dynamically fetched
- **K8s operator**: Make it possible to dynamically expose ssh servers on pods using annotations.

## Configuration

The server is configured using a YAML configuration file (default: `config.yaml`). Here's the structure:

```yaml
# SSH Proxy Configuration - Routing rules based on username
routes:
  # Alice: Password authentication only using bcrypt hash
  - username: "alice"
    target:
      host: "192.168.1.100"
      port: 22
      user: "alice"
      auth:
        type: "password"
        password: "alice-target-password"
    auth:
      - type: "password"
        # bcrypt hash of "alice-secret"
        password_hash: "$2a$10$8K1p/a0dqbgX8K1p/a0dqOGp3lZ4wRcUWUzU8K1p/a0dq"
        hash_type: "bcrypt"
  
  # Bob: Public key authentication only
  - username: "bob"
    target:
      host: "192.168.1.101"
      port: 22
      user: "bob"
      auth:
        type: "key"
        key_path: "/path/to/bob/target/key"
    auth:
      - type: "key"
        authorized_keys:
          - "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDw+3X0... bob@example.com"
          - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG5X0... bob@laptop"
  
  # Charlie: Multiple auth methods - passwords AND public key
  - username: "charlie"
    target:
      host: "example.com"
      port: 2222
      user: "charlie"
      auth:
        type: "password"
        password: "charlie-target-password"
    auth:
      - type: "password"
        password: "charlie-password1"
      - type: "password"
        password_hash: "$2a$10$abcdefghijklmnop..."
        hash_type: "bcrypt"
      - type: "key"
        authorized_keys:
          - "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDxyz... charlie@work"
```

### Configuration Fields

#### Route Configuration
- `username`: The username that will be authenticated and routed
- `target.host`: Target SSH server hostname/IP
- `target.port`: Target SSH server port (default: 22)
- `target.user`: Username to use when connecting to the target server
- `target.auth.type`: Authentication type for connecting to target ("password" or "key")
- `target.auth.password`: Password for target server authentication
- `target.auth.key_path`: Path to private key for target server authentication
- `auth`: Array of authentication methods for client connections

#### Client Authentication Methods
- `auth[].type`: Authentication type - "password" or "key"
- `auth[].password`: Plain text password (not recommended for production)
- `auth[].password_hash`: Hashed password for secure storage
- `auth[].hash_type`: Hash algorithm used ("bcrypt" recommended)
- `auth[].authorized_keys`: Array of public keys for key-based authentication

**Note**: Multiple authentication methods can be configured per user. Clients can authenticate using any of the configured methods.

### Password Hashing

For security, passwords should be stored as hashes rather than plaintext. Supported hash types:

- **bcrypt** (recommended): Use `bcrypt` command or Go's `bcrypt` package to generate hashes

Example generating bcrypt hash:
```bash
# Using htpasswd
htpasswd -bnBC 10 "" password | tr -d ':\n'

# Using online bcrypt generators or custom Go program
```

## Usage

### Building

#### Using Make (Recommended)
```bash
# Format, lint, and build
make all

# Just build
make build

# Run tests
make test

# Format code
make fmt

# Lint code
make lint
```

#### Manual Building
```bash
go mod tidy
go build -o ssh-proxy
```

The project uses a modular package structure:
- `pkg/config/`: Configuration loading and types
- `pkg/proxy/`: SSH proxy implementation
- `test/integration/`: Integration tests using Ginkgo

### Running with Docker

The project includes Docker support for easy testing and deployment.

#### Quick Start with Docker Compose

1. **Start the test environment**:
```bash
docker-compose up -d
```

This will start:
- SSH proxy server on port 2222
- Test SSH server for Alice on port 2223
- Test SSH server for Bob on port 2224

2. **Test the proxy**:
```bash
# Connect as alice (will be routed to alice's SSH server)
ssh alice@localhost -p 2222
# Password: alice-secret

# Connect as bob (will be routed to bob's SSH server)
ssh bob@localhost -p 2222
# Password: bob-secret
```

3. **Stop the environment**:
```bash
docker-compose down
```

### Using SSH Config File

For easier testing, use the provided SSH config file:

```bash
# Use the SSH config file for convenient connections
ssh -F test/ssh_config alice-proxy   # Connect as alice through proxy
ssh -F test/ssh_config bob-proxy     # Connect as bob through proxy

# Or copy to your SSH config directory
cp test/ssh_config ~/.ssh/config_proxy
ssh -F ~/.ssh/config_proxy alice-proxy
```

The `test/ssh_config` file includes predefined hosts:
- `alice-proxy`: Connect as alice through the SSH proxy
- `bob-proxy`: Connect as bob through the SSH proxy  
- `alice-direct`: Connect directly to alice's target server
- `bob-direct`: Connect directly to bob's target server

#### Building Docker Image

```bash
# Build the SSH proxy Docker image
docker build -t ssh-proxy .

# Run with custom configuration
docker run -p 2222:2222 -v $(pwd)/config.yaml:/root/config.yaml:ro ssh-proxy
```

### Command Line Options

```bash
# Basic usage with default configuration
./ssh-proxy

# Custom configuration file
./ssh-proxy --config /path/to/config.yaml

# Specify host and port
./ssh-proxy --host localhost --port 3333

# Configure logging
./ssh-proxy --log-level debug --log-json --log-source

# Show help
./ssh-proxy --help
```

#### Available Options
- `--config`: Path to configuration file (default: "config.yaml")
- `--host`: Host to bind the SSH server to (default: "0.0.0.0")
- `--port`: Port to bind the SSH server to (default: 2222)
- `--hostkey`: Path to SSH host key (default: "/etc/ssh/ssh_host_rsa_key")
- `--log-level`: Log level - debug, info, warn, error (default: "info")
- `--log-source`: Include source location in log messages
- `--log-json`: Use JSON log format instead of text
- `--help`: Show help message

### Running

### Connecting
Once the proxy is running, clients can connect using standard SSH clients:

```bash
# Connect as alice (will be routed to 192.168.1.100:22)
ssh alice@localhost -p 2222

# Connect as bob (will be routed to 192.168.1.101:22)  
ssh bob@localhost -p 2222
```

## How It Works

1. **Client Connection**: Client connects to the SSH proxy server
2. **Authentication**: Proxy authenticates the user based on the configured authentication method
3. **Route Lookup**: Proxy looks up the target server based on the authenticated username
4. **Target Connection**: Proxy establishes a connection to the target SSH server
5. **Protocol Proxying**: All SSH protocol messages (channels, requests, data) are transparently proxied between client and target

## Security Considerations

- **Host Key Verification**: The current implementation uses `ssh.InsecureIgnoreHostKey()` for simplicity. In production, implement proper host key verification
- **Authentication Storage**: Store authentication credentials securely (e.g., encrypted configuration, external auth providers)
- **Access Control**: Implement additional access controls and logging as needed
- **Key Management**: Securely manage and rotate SSH keys

## Example Use Cases

- **Development Environment**: Route developers to their individual development servers
- **Multi-tenant Systems**: Isolate users to their respective environments
- **Load Balancing**: Distribute users across multiple backend SSH servers
- **Audit and Logging**: Centralize SSH access through a single entry point

## Dependencies

- `golang.org/x/crypto/ssh`: SSH protocol implementation
- `gopkg.in/yaml.v2`: YAML configuration file parsing
- `golang.org/x/crypto/bcrypt`: Password hashing for secure authentication
- `log/slog`: Structured logging (Go 1.21+)
- `github.com/onsi/ginkgo/v2` & `github.com/onsi/gomega`: Testing framework (dev dependency)
- Standard Go library for networking and system operations