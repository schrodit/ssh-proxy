# SSH Proxy Server

A Go-based SSH proxy server that routes connections to different SSH targets based on the authenticated username.

Example Use Cases

- **Development Environment**: Route developers to their individual development servers
- **Multi-tenant Systems**: Isolate users to their respective environments
- **Load Balancing**: Distribute users across multiple backend SSH servers
- **Audit and Logging**: Centralize SSH access through a single entry point

## Features

- **Username-based routing**: Route SSH connections to different target servers based on the connecting username
- **Regex-based routing**: Match usernames with regex patterns and use captured groups in target host templates
- **Dynamic host templates**: Use Go templates in the target host field with regex capture groups
- **Multiple authentication methods**: Support for both password and public key authentication
- **Target host key verification**: Require explicit `host_key` or `insecure: true` per target for secure connections
- **Automatic host key generation**: Generates host keys automatically if not provided

## Planned Features
- **Improve security**
  - Do not store passwords in plain text/Support secret stores or external authentication
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
- **K8s operator**: Make it possible to dynamically expose ssh servers on pods using annotations.

## How It Works

1. **Client Connection**: Client connects to the SSH proxy server
2. **Authentication**: Proxy authenticates the user based on the configured authentication method
3. **Route Lookup**: Proxy looks up the target server based on the authenticated username (exact match first, then regex patterns)
4. **Host Resolution**: If the route uses a regex pattern, the target host is resolved using Go templates with captured groups
5. **Target Connection**: Proxy establishes a connection to the target SSH server
5. **Protocol Proxying**: All SSH protocol messages (channels, requests, data) are transparently proxied between client and target

## Configuration

The server is configured using a YAML configuration file.

See [Configuration](./docs/configuration.md) for complete documentation.

```yaml
# SSH Proxy Configuration - Routing rules based on username
routes:
  # Alpha: Multiple auth methods - passwords AND public key
  - username: "alpha"
    target:
      host: "example.com"
      port: 2222
      user: "charlie"
      insecure: true
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

  # Dynamic routing with regex: Match usernames like "dev-myapp", "prod-api"
  - usernameRegex: "^(?P<env>dev|staging|prod)-(?P<service>.+)$"
    target:
      host: "{{.Named.env}}-{{.Named.service}}.internal"
      port: 22
      user: "deploy"
      insecure: true
      auth:
        type: "password"
        password: "deploy-secret"
    auth:
      - type: "password"
        password: "shared-secret"
```

## Quick Start

### Try It Out with Docker Compose

The fastest way to get started is using the included Docker Compose setup, which spins up the proxy along with example target SSH servers:

```bash
docker-compose up -d
```

This starts the SSH proxy on port 2222 with two test SSH servers. You can immediately test it:

```bash
# Connect as alice (routed to alice's SSH server)
ssh alice@localhost -p 2222
# Password: alice-secret

# Connect as bob (routed to bob's SSH server)
ssh bob@localhost -p 2222
# Password: bob-secret
```

Stop the environment with `docker-compose down`.

### Production Deployment with Helm

For production use, deploy to Kubernetes using the included Helm chart:

```bash
helm install ssh-proxy ./chart \
  --set proxy.config.routes[0].username=alice \
  --set proxy.config.routes[0].target.host=192.168.1.100
```

Or provide a values file with your full routing configuration:

```bash
helm install ssh-proxy ./chart -f my-values.yaml
```

See [chart/values.yaml](./chart/values.yaml) for all available Helm values.

## Development

For building, running, testing, and detailed usage instructions, see the [Development Guide](./docs/development.md).
