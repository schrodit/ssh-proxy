package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/schrodit/ssh-proxy/pkg/config"
	"github.com/schrodit/ssh-proxy/pkg/proxy"
)

func main() {
	// Command line flags
	var (
		configPath  = flag.String("config", "config.yaml", "Path to configuration file")
		host        = flag.String("host", "0.0.0.0", "Host to bind the SSH server to")
		port        = flag.Int("port", 2222, "Port to bind the SSH server to")
		hostKeyPath = flag.String("hostkey", "/etc/ssh/ssh_host_rsa_key", "Path to SSH host key")
		// Logging configuration
		logLevel  = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
		logSource = flag.Bool("log-source", false, "Include source location in log messages")
		logJSON   = flag.Bool("log-json", false, "Use JSON log format instead of text")
		showHelp  = flag.Bool("help", false, "Show help message")
	)

	// Custom usage function
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SSH Proxy Server\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s --config=config.yaml --port=2222\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --log-level=debug --log-json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --host=localhost --port=3333 --log-source\n", os.Args[0])
	}

	flag.Parse()

	// Show help if requested
	if *showHelp {
		flag.Usage()
		os.Exit(0)
	}

	// Validate flags
	if err := validateFlags(*port, *logLevel); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		flag.Usage()
		os.Exit(1)
	}

	// Configure slog based on flags
	logger := configureLogger(*logLevel, *logSource, *logJSON)
	slog.SetDefault(logger)

	configManager, err := config.NewConfigManager(*configPath)
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := configManager.Close(); err != nil {
			slog.Error("Failed to close config manager", "error", err)
			os.Exit(1)
		}
	}()

	server := proxy.New(configManager, *host, *port, *hostKeyPath)
	slog.Info("Starting SSH proxy server", "host", *host, "port", *port)
	if err := server.Start(); err != nil {
		slog.Error("Failed to start SSH proxy", "error", err)
		os.Exit(1)
	}
}

// configureLogger sets up the slog logger based on the provided configuration flags
func configureLogger(logLevel string, addSource bool, useJSON bool) *slog.Logger {
	// Parse log level
	level := parseLogLevel(logLevel)

	// Configure handler options
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: addSource,
	}

	// Create appropriate handler
	var handler slog.Handler
	if useJSON {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}

// parseLogLevel converts a string log level to slog.Level
func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		// Default to info level and log a warning
		slog.Warn("Invalid log level, defaulting to info", "provided", level)
		return slog.LevelInfo
	}
}

// validateFlags validates command line flag values
func validateFlags(port int, logLevel string) error {
	// Validate port range
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", port)
	}

	// Validate log level
	switch strings.ToLower(logLevel) {
	case "debug", "info", "warn", "warning", "error":
		// Valid log levels
	default:
		return fmt.Errorf("invalid log level '%s', must be one of: debug, info, warn, error", logLevel)
	}

	return nil
}
