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
      # Known host key for secure verification
      host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG5X0..."
      auth:
        type: "password"
        password: "alice-target-password"
    auth:
      - type: "password"
        # bcrypt hash of "alice-secret"
        password_hash: "$2a$10$8K1p/a0dqbgX8K1p/a0dqOGp3lZ4wRcUWUzU8K1p/a0dq"
        hash_type: "bcrypt"
  
  # Bob: Public key authentication only (insecure target)
  - username: "bob"
    target:
      host: "192.168.1.101"
      port: 22
      user: "bob"
      # Explicitly skip host key verification (not recommended for production)
      insecure: true
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

  # External authentication: Delegate auth to an external webhook service
  - username: "webhook-user"
    target:
      host: "fallback.example.com"
      port: 22
      user: "deploy"
      insecure: true
      auth:
        type: "password"
        password: "fallback-password"
    auth:
      - type: "external_auth"
        external_auth:
          url: "https://auth.example.com/ssh/verify"
          headers:
            Authorization: "Bearer my-api-token"
          timeout: "5s"
```

### Configuration Fields

#### Route Configuration
- `username`: The username that will be authenticated and routed (exact match)
- `usernameRegex`: A regex pattern to match usernames (supports named and positional capture groups)
- `target.host`: Target SSH server hostname/IP (supports Go templates when using `usernameRegex`)
- `target.port`: Target SSH server port (default: 22)
- `target.user`: Username to use when connecting to the target server
- `target.host_key`: Known public key of the target server for host key verification (e.g., `"ssh-ed25519 AAAA..."`). Required if `insecure` is not set.
- `target.insecure`: Set to `true` to skip host key verification. Required if `host_key` is not set. **Not recommended for production.**
- `target.auth.type`: Authentication type for connecting to target ("password" or "key")
- `target.auth.password`: Password for target server authentication
- `target.auth.key_path`: Path to private key for target server authentication
- `auth`: Array of authentication methods for client connections

**Note**: Use either `username` (exact match) or `usernameRegex` (regex match) per route, not both. Exact matches are evaluated before regex matches.

**Note**: Every target must explicitly set either `host_key` or `insecure: true`. The configuration will fail to load if neither is specified.

#### Host Templates

When using `usernameRegex`, the `target.host` field supports Go templates with the following data:

- `{{.Username}}`: The original username that connected
- `{{.Named.<name>}}`: Named capture groups from the regex (e.g., `(?P<env>...)` → `{{.Named.env}}`)
- `{{index .Groups N}}`: Positional capture groups (index 0 = full match, 1 = first group, etc.)

Example:
```yaml
# Username "prod-api" with regex "^(?P<env>dev|prod)-(?P<service>.+)$"
# resolves host to "prod-api.internal"
usernameRegex: "^(?P<env>dev|prod)-(?P<service>.+)$"
target:
  host: "{{.Named.env}}-{{.Named.service}}.internal"
```

#### Client Authentication Methods
- `auth[].type`: Authentication type - "password", "key", or "external_auth"
- `auth[].password`: Plain text password (not recommended for production)
- `auth[].password_hash`: Hashed password for secure storage
- `auth[].hash_type`: Hash algorithm used ("bcrypt" recommended)
- `auth[].authorized_keys`: Array of public keys for key-based authentication
- `auth[].external_auth`: External webhook authentication configuration (see below)

**Note**: Multiple authentication methods can be configured per user. Clients can authenticate using any of the configured methods.

### External Authentication (Webhook)

The `external_auth` type delegates authentication to an external HTTP service. When a client connects, the proxy sends a JSON POST request with the user's credentials to the configured webhook URL. The webhook decides whether to allow or deny the connection based on the HTTP status code it returns.

#### Configuration

```yaml
auth:
  - type: "external_auth"
    external_auth:
      url: "https://auth.example.com/ssh/verify"
      headers:
        Authorization: "Bearer my-api-token"
        X-Custom-Header: "value"
      timeout: "10s"
```

#### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `external_auth.url` | Yes | The URL of the webhook endpoint that will receive the authentication request. |
| `external_auth.headers` | No | A map of HTTP headers to include in the request (e.g., API keys, bearer tokens). |
| `external_auth.timeout` | No | Timeout for the HTTP request as a Go duration string (e.g., `"5s"`, `"30s"`). Defaults to `"5s"`. |

#### Webhook Request

The proxy sends a `POST` request with `Content-Type: application/json` to the configured URL. The JSON body has the following structure:

```json
{
  "username": "alice",
  "auth_type": "password",
  "password": "secret"
}
```

For public key authentication:

```json
{
  "username": "alice",
  "auth_type": "public_key",
  "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5..."
}
```

| Field | Description |
|-------|-------------|
| `username` | The SSH username the client is connecting with. |
| `auth_type` | Either `"password"` or `"public_key"`. |
| `password` | The password provided by the client (only for `password` auth). |
| `public_key` | The public key presented by the client in OpenSSH authorized_keys format (only for `public_key` auth). |

#### Webhook Response

The webhook communicates its decision via HTTP status code:

| Status Code | Meaning |
|-------------|---------|
| `200 OK` | User is authenticated — the connection is allowed. |
| `401 Unauthorized` | User is not authenticated — the connection is rejected. |
| Any other code | Treated as an error — the connection is rejected and the error is logged. |

The response body is ignored.

#### Example Webhook Server (Go)

```go
http.HandleFunc("/ssh/verify", func(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Username string `json:"username"`
        AuthType string `json:"auth_type"`
        Password string `json:"password,omitempty"`
        PublicKey string `json:"public_key,omitempty"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }

    // Your authentication logic here
    if req.Username == "alice" && req.Password == "secret" {
        w.WriteHeader(http.StatusOK)
        return
    }

    w.WriteHeader(http.StatusUnauthorized)
})
```

### Password Hashing

For security, passwords should be stored as hashes rather than plaintext. Supported hash types:

- **bcrypt** (recommended): Use `bcrypt` command or Go's `bcrypt` package to generate hashes

Example generating bcrypt hash:
```bash
# Using htpasswd
htpasswd -bnBC 10 "" password | tr -d ':\n'

# Using online bcrypt generators or custom Go program
```
