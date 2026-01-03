package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
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
		healthPort  = flag.Int("health-port", 8080, "Port for HTTP health check endpoint")
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
		fmt.Fprintf(os.Stderr, "  %s --host=localhost --port=3333 --health-port=9090\n", os.Args[0])
	}

	flag.Parse()

	// Show help if requested
	if *showHelp {
		flag.Usage()
		os.Exit(0)
	}

	// Validate flags
	if err := validateFlags(*port, *healthPort, *logLevel); err != nil {
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

	// Create HTTP health check server
	healthServer := createHealthServer(*healthPort, configManager)

	// Create SSH proxy server
	sshServer := proxy.New(configManager, *host, *port, *hostKeyPath)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start servers concurrently
	var wg sync.WaitGroup

	// Start health check server
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("Starting health check server", "port", *healthPort)
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Health check server failed", "error", err)
			cancel()
		}
	}()

	// Start SSH proxy server
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("Starting SSH proxy server", "host", *host, "port", *port)
		if err := sshServer.Start(); err != nil {
			slog.Error("Failed to start SSH proxy", "error", err)
			cancel()
		}
	}()

	// Wait for shutdown signal or context cancellation
	select {
	case sig := <-sigCh:
		slog.Info("Received shutdown signal", "signal", sig)
	case <-ctx.Done():
		slog.Info("Shutting down due to error")
	}

	// Graceful shutdown
	slog.Info("Shutting down servers...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// Shutdown health server
	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("Health server shutdown error", "error", err)
	}

	// Note: SSH server doesn't have graceful shutdown in the current implementation
	// You might want to add that to the proxy package

	wg.Wait()
	slog.Info("Shutdown complete")
}

// createHealthServer creates a gin HTTP server with health check endpoint
func createHealthServer(port int, configManager *config.ConfigManager) *http.Server {
	// Set gin to release mode to reduce log noise
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()

	// Add custom middleware for logging
	router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC3339),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	}))

	router.Use(gin.Recovery())

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		// Get current configuration to verify it's loaded
		config := configManager.GetConfig()
		routeCount := 0
		if config != nil && config.Routes != nil {
			routeCount = len(config.Routes)
		}

		response := gin.H{
			"status":    "ok",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"routes":    routeCount,
			"service":   "ssh-proxy",
			"version":   "1.0.0", // You might want to make this dynamic
		}

		c.JSON(http.StatusOK, response)
	})

	// Readiness endpoint (same as health for now, but can be enhanced)
	router.GET("/ready", func(c *gin.Context) {
		config := configManager.GetConfig()
		if config == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":    "not ready",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"reason":    "configuration not loaded",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":    "ready",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"service":   "ssh-proxy",
		})
	})

	// Metrics endpoint (basic info)
	router.GET("/metrics", func(c *gin.Context) {
		config := configManager.GetConfig()
		routeCount := 0
		if config != nil && config.Routes != nil {
			routeCount = len(config.Routes)
		}

		// Simple text metrics format
		metrics := fmt.Sprintf(`# HELP ssh_proxy_routes_total Total number of configured routes
# TYPE ssh_proxy_routes_total gauge
ssh_proxy_routes_total %d
`, routeCount)

		c.Header("Content-Type", "text/plain")
		c.String(http.StatusOK, metrics)
	})

	return &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: router,
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
func validateFlags(port, healthPort int, logLevel string) error {
	// Validate port range
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", port)
	}

	// Validate health port range
	if healthPort < 1 || healthPort > 65535 {
		return fmt.Errorf("health-port must be between 1 and 65535, got %d", healthPort)
	}

	// Check for port conflicts
	if port == healthPort {
		return fmt.Errorf("ssh port and health check port cannot be the same (%d)", port)
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
