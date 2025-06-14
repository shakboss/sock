package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"

	"log/slog"

	"github.com/shakboss/sock/tree/main/internal/config"
)

var (
	configPath = flag.String("config", "", "Path to config file")
)

func main() {
	flag.Parse()

	// Load configuration
	cfg := config.DefaultConfig()
	if *configPath != "" {
		if err := config.LoadFromFile(*configPath, cfg); err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
	}

	// Initialize logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout))

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start servers
	var wg sync.WaitGroup

	// Start SSH server
	if cfg.SSH.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := startSSHServer(ctx, cfg.SSH, logger, cfg); err != nil {
				logger.Error("SSH server error", "error", err)
			}
		}()
	}

	// Start SOCKS5 server
	if cfg.SOCKS5.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := startSOCKS5Server(ctx, cfg.SOCKS5, logger); err != nil {
				logger.Error("SOCKS5 server error", "error", err)
			}
		}()
	}

	// Start DNS server
	if cfg.DNS.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := startDNSServer(ctx, cfg.DNS, logger); err != nil {
				logger.Error("DNS server error", "error", err)
			}
		}()
	}

	logger.Info("SocksIP server started. Press Ctrl+C to stop.")

	// Wait for shutdown signal
	<-sigCh
	logger.Info("Shutting down server...")
	cancel()

	// Wait for all servers to shut down
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("Server stopped gracefully")
	case <-sigCh:
		logger.Info("Forcing shutdown...")
	}
}

// startSSHServer starts the SSH server
func startSSHServer(ctx context.Context, cfg config.SSHConfig, logger *slog.Logger, config *config.Config) error {
	// Generate host key if it doesn't exist
	privateKey, err := generateOrLoadHostKey(cfg.HostKeyPath, logger)
	if err != nil {
		return fmt.Errorf("failed to generate or load SSH host key: %v", err)
	}

	// Parse private key
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	// Configure SSH server
	sshConfig := &ssh.ServerConfig{
		MaxAuthTries:         cfg.MaxAuthTries,
		ServerVersion:        cfg.Banner,
		PublicKeyCallback:    publicKeyCallback,
		PasswordCallback:     passwordCallback,
		NoClientAuth:         false,
		NoClientAuthCallback: nil,
	}

	sshConfig.AddHostKey(signer)

	// Start listening
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", cfg.ListenAddr, err)
	}
	defer listener.Close()

	logger.Info("SSH server listening on %s", cfg.ListenAddr)

	// Handle incoming connections
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				logger.Error("failed to accept SSH connection", "error", err)
				continue
			}

			go handleSSHConnection(conn, sshConfig, logger, config)
		}
	}
}

// generateOrLoadHostKey generates a new SSH private key and saves it to the specified path
func generateOrLoadHostKey(path string, logger *slog.Logger) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.Info("generating new SSH host key", "path", path)

		// Create directory if it doesn't exist
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}

		// Generate private key
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, err
		}

		// Create private key file
		privateKeyFile, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return nil, err
		}
		defer privateKeyFile.Close()

		// Encode private key to PEM format
		privateKeyPEM := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}

		if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
			return nil, err
		}

		return privateKeyPEM.Bytes, nil
	}

	// Load host key
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read host key: %v", err)
	}

	return keyBytes, nil
}

// handleSSHConnection handles an incoming SSH connection
func handleSSHConnection(conn net.Conn, config *ssh.ServerConfig, logger *slog.Logger, cfg *config.Config) {
	defer conn.Close()
	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		logger.Warn("failed to complete SSH handshake", "error", err, "remote_addr", conn.RemoteAddr())
		return
	}

	logger.Info("new SSH connection", "user", sconn.User(), "version", string(sconn.ClientVersion()))
	go ssh.DiscardRequests(reqs)

	// Service the multiplexed channels
	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "session":
			// We don't implement shell, just accept and discard to keep client happy
			channel, requests, err := newChannel.Accept()
			if err != nil {
				logger.Error("could not accept session channel", "error", err)
				continue
			}
			go ssh.DiscardRequests(requests)
			go io.Copy(io.Discard, channel)

		case "direct-tcpip":
			go handleDirectTCPIP(newChannel, sconn, logger, cfg)

		default:
			logger.Warn("rejected unknown channel type", "type", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

// handleDirectTCPIP handles an SSH direct-tcpip channel request, which is used for port forwarding.
// It connects to the destination through the SOCKS5 server.
func handleDirectTCPIP(newChannel ssh.NewChannel, sconn *ssh.ServerConn, logger *slog.Logger, cfg *config.Config) {
	// 1. Parse the destination address from the request
	var req struct {
		DestAddr string
		DestPort uint32
		OrigAddr string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		logger.Error("failed to unmarshal direct-tcpip request", "error", err)
		newChannel.Reject(ssh.ConnectionFailed, "parse error")
		return
	}
	dest := net.JoinHostPort(req.DestAddr, fmt.Sprintf("%d", req.DestPort))
	logger.Info("received direct-tcpip request", "user", sconn.User(), "dest", dest)

	// 2. Prepare SOCKS5 authentication if needed
	var auth proxy.Auth
	if len(cfg.Users) > 0 {
		username := sconn.Permissions.Extensions["username"]
		password := sconn.Permissions.Extensions["password"]
		if username == "" || password == "" {
			logger.Error("no credentials found in SSH session for SOCKS5 auth")
			newChannel.Reject(ssh.ConnectionFailed, "internal auth error")
			return
		}
		auth = &proxy.UsernamePassword{
			User:     username,
			Password: password,
		}
	}

	// 3. Dial the destination through the SOCKS5 server
	dialer, err := proxy.SOCKS5("tcp", cfg.SocksServerAddr, auth, proxy.Direct)
	if err != nil {
		logger.Error("failed to create SOCKS5 dialer", "error", err)
		newChannel.Reject(ssh.ConnectionFailed, "internal server error")
		return
	}

	targetConn, err := dialer.Dial("tcp", dest)
	if err != nil {
		logger.Error("failed to connect to destination via SOCKS5", "dest", dest, "error", err)
		newChannel.Reject(ssh.ConnectionFailed, "connection refused")
		return
	}

	// 4. Accept the SSH channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		logger.Error("could not accept direct-tcpip channel", "error", err)
		targetConn.Close()
		return
	}
	go ssh.DiscardRequests(requests)

	// 5. Proxy data between the two connections
	logger.Info("SSH forwarding established", "user", sconn.User(), "dest", dest)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer channel.Close()
		defer targetConn.Close()
		io.Copy(channel, targetConn)
	}()
	go func() {
		defer wg.Done()
		defer channel.Close()
		defer targetConn.Close()
		io.Copy(targetConn, channel)
	}()
	wg.Wait()
	logger.Info("SSH forwarding connection closed", "user", sconn.User(), "dest", dest)
}

// publicKeyCallback handles SSH public key authentication
func publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	// In a real implementation, validate the public key against authorized keys
	return nil, nil
}

// passwordCallback handles SSH password authentication
func passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	// In a real implementation, validate the username and password
	// For now, just return a dummy permission with credentials
	return &ssh.Permissions{
		Extensions: map[string]string{
			"username": conn.User(),
			"password": string(password),
		},
	}, nil
}

// startSOCKS5Server starts the SOCKS5 server
func startSOCKS5Server(ctx context.Context, cfg config.SOCKS5Config, logger *slog.Logger) error {
	// TODO: Implement SOCKS5 server
	logger.Info("SOCKS5 server would start on %s (not implemented)", cfg.ListenAddr)
	<-ctx.Done()
	return nil
}

// startDNSServer starts the DNS server
func startDNSServer(ctx context.Context, cfg config.DNSConfig, logger *slog.Logger) error {
	// TODO: Implement DNS server
	logger.Info("DNS server would start on %s (not implemented)", cfg.ListenAddr)
	<-ctx.Done()
	return nil
}
