## Configuration

The server is configured using a YAML configuration file (default: `config.yaml`). Here's the structure:

```yaml
# SSH Proxy Configuration - Routing rules based on username
server:
  auth:
    password:
      enabled: true
    publickey:
      enabled: true
    keyboardInteractive:
      enabled: true

routes:
  # Alice: Password authentication only using bcrypt hash
  - username: "alice"
    target:
      host: "192.168.1.100"
      port: 22
      user: "alice"
      # Known host key for secure verification
      hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG5X0..."
      auth:
        type: "password"
        password: "alice-target-password"
    auth:
      - type: "password"
        # bcrypt hash of "alice-secret"
        passwordHash: "$2a$10$8K1p/a0dqbgX8K1p/a0dqOGp3lZ4wRcUWUzU8K1p/a0dq"
        hashType: "bcrypt"
  
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
        keyPath: "/path/to/bob/target/key"
    auth:
      - type: "key"
        authorizedKeys:
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
        passwordHash: "$2a$10$abcdefghijklmnop..."
        hashType: "bcrypt"
      - type: "key"
        authorizedKeys:
          - "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDxyz... charlie@work"

  # Dana: Keyboard-interactive challenge flow. Only available via externalAuth
  - username: "dana"
    target:
      host: "vpn.internal"
      port: 22
      user: "dana"
      insecure: true
      auth:
        type: "password"
        password: "dana-target-password"
    auth:
      - type: "externalAuth"
        externalAuth:
          url: "https://auth.example.com/ssh/challenge"
          timeout: "10s"

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
        externalAuth:
          url: "https://auth.example.com/ssh/verify"
          headers:
            Authorization: "Bearer my-api-token"
          timeout: "5s"
```

### Configuration Fields

#### Server Configuration
- `server.auth.password.enabled`: Whether the proxy SSH server offers password authentication
- `server.auth.publickey.enabled`: Whether the proxy SSH server offers public key authentication
- `server.auth.keyboard_interactive.enabled`: Whether the proxy SSH server offers keyboard-interactive authentication

**Note**: All server authentication methods are enabled by default when omitted.

**Note**: At least one server authentication method must remain enabled or the configuration will fail to load.

#### Route Configuration
- `username`: The username that will be authenticated and routed (exact match)
- `usernameRegex`: A regex pattern to match usernames (supports named and positional capture groups)
- `target.host`: Target SSH server hostname/IP (supports Go templates when using `usernameRegex`)
- `target.port`: Target SSH server port (default: 22)
- `target.user`: Username to use when connecting to the target server
- `target.hostKey`: Known public key of the target server for host key verification (e.g., `"ssh-ed25519 AAAA..."`). Required if `insecure` is not set.
- `target.insecure`: Set to `true` to skip host key verification. Required if `hostKey` is not set. **Not recommended for production.**
- `target.auth.type`: Authentication type for connecting to target ("password" or "key")
- `target.auth.password`: Password for target server authentication
- `target.auth.keyPath`: Path to private key for target server authentication
- `auth`: Array of authentication methods for client connections

**Note**: Use either `username` (exact match) or `usernameRegex` (regex match) per route, not both. Exact matches are evaluated before regex matches.

**Note**: Every target must explicitly set either `hostKey` or `insecure: true`. The configuration will fail to load if neither is specified.

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
- `auth[].passwordHash`: Hashed password for secure storage
- `auth[].hashType`: Hash algorithm used ("bcrypt" recommended)
- `auth[].authorizedKeys`: Array of public keys for key-based authentication
- `auth[].externalAuth`: External webhook authentication configuration (see below)

**Note**: Multiple authentication methods can be configured per user. Clients can authenticate using any of the configured methods.

### External Authentication (Webhook)

The `external_auth` type delegates authentication to an external HTTP service. When a client connects, the proxy sends a JSON POST request with the user's credentials to the configured webhook URL. The webhook decides whether to allow or deny the connection based on the HTTP status code it returns.

#### Configuration

```yaml
auth:
  - type: "external_auth"
    externalAuth:
      url: "https://auth.example.com/ssh/verify"
      headers:
        Authorization: "Bearer my-api-token"
        X-Custom-Header: "value"
      timeout: "10s"
```

#### Fields

| Field | Required | Description |
|-------|----------|-----------|
| `externalAuth.url` | Yes | The URL of the webhook endpoint that will receive the authentication request. |
| `externalAuth.headers` | No | A map of HTTP headers to include in the request (e.g., API keys, bearer tokens). |
| `externalAuth.timeout` | No | Timeout for the HTTP request as a Go duration string (e.g., `"5s"`, `"30s"`). Defaults to `"5s"`. |

#### Webhook Request

The proxy sends a `POST` request with `Content-Type: application/json` to the configured URL. Every auth webhook request includes the same base fields:

```json
{
  "username": "alice",
  "auth_type": "password"
}
```

Depending on `auth_type`, the request then includes auth-specific fields.

For password authentication:

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

### Keyboard-Interactive Authentication

The `keyboard_interactive` type delegates RFC 4256 keyboard-interactive authentication to a dedicated webhook endpoint. This is useful for OTP, MFA, or custom challenge/response flows that need one or more prompt rounds.

#### Configuration

```yaml
auth:
  - type: "keyboard_interactive"
    externalAuth:
      url: "https://auth.example.com/ssh/challenge"
      headers:
        Authorization: "Bearer my-api-token"
      timeout: "10s"
```

#### Fields

| Field | Required | Description |
|-------|----------|-----------|
| `externalAuth.url` | Yes | The URL of the dedicated challenge webhook endpoint. |
| `externalAuth.headers` | No | A map of HTTP headers to include in the request. |
| `externalAuth.timeout` | No | Timeout for the HTTP request as a Go duration string. Defaults to `"5s"`. |

#### Webhook Request

Keyboard-interactive requests use the same base webhook fields and add challenge state for each round.

The initial challenge request looks like this:

```json
{
  "username": "alice",
  "auth_type": "keyboard_interactive",
  "session_id": "deadbeef",
  "challenge_round": 0
}
```

After the webhook returns a `202 Accepted` challenge, the proxy prompts the SSH client and sends the next round including the collected answers:

```json
{
  "username": "alice",
  "auth_type": "keyboard_interactive",
  "session_id": "deadbeef",
  "challenge_round": 1,
  "answers": ["123456"]
}
```

#### Webhook Response

| Status Code | Meaning |
|-------------|---------|
| `200 OK` | Authentication succeeded. |
| `401 Unauthorized` | Authentication failed. |
| `202 Accepted` | Present another keyboard-interactive challenge using the JSON response body below, then expect the next request to include the user's answers. |

For `202 Accepted`, the response body must contain:

```json
{
  "name": "MFA required",
  "instruction": "Enter your one-time code",
  "questions": ["OTP"],
  "echos": [false]
}
```

#### Example Webhook Server (Go)

```go
http.HandleFunc("/ssh/verify", func(w http.ResponseWriter, r *http.Request) {
    payload, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }

    var base struct {
        Username string `json:"username"`
        AuthType string `json:"auth_type"`
    }
    if err := json.Unmarshal(payload, &base); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }

    switch base.AuthType {
    case "password":
        // Decode payload into your password request type here.
    case "public_key":
        // Decode payload into your public-key request type here.
    case "keyboard_interactive":
        // Decode payload into your keyboard-interactive request type here.
        // Return 202 with questions, 200 on success, or 401 on denial.
    }
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
