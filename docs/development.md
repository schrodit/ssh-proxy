## Development

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

### Connecting

Once the proxy is running, clients can connect using standard SSH clients:

```bash
# Connect as alice (will be routed to 192.168.1.100:22)
ssh alice@localhost -p 2222

# Connect as bob (will be routed to 192.168.1.101:22)  
ssh bob@localhost -p 2222
```
