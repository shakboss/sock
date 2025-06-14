package sshserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"e:/socksip-server/internal/config"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

// ListenAndServe starts the SSH server.
func ListenAndServe(ctx context.Context, cfg config.SSHConfig, logger *slog.Logger, appCfg *config.Config) error {
	privateKeyBytes, err := generateOrLoadHostKey(cfg.HostKeyPath, logger)
	if err != nil {
		return fmt.Errorf("failed to get host key: %w", err)
	}

	privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse host key: %w", err)
	}

	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			logger.Debug("SSH login attempt", "user", c.User(), "remote_addr", c.RemoteAddr())

			// HWID Check
			clientVersion := string(c.ClientVersion())
			hwid := extractHWID(clientVersion)

			for _, user := range appCfg.Users {
				if user.Username == c.User() && user.Password == string(pass) {
					if user.Hwid != "" && user.Hwid != hwid {
						logger.Warn("SSH login failed: HWID mismatch", "user", c.User(), "expected_hwid", user.Hwid, "got_hwid", hwid)
						return nil, fmt.Errorf("invalid credentials")
					}
					logger.Info("SSH user authenticated", "user", c.User())
					// Store credentials for SOCKS5 proxying
					return &ssh.Permissions{
						Extensions: map[string]string{
							"username": user.Username,
							"password": user.Password,
						},
					}, nil
				}
			}

			logger.Warn("SSH login failed: invalid credentials", "user", c.User())
			return nil, fmt.Errorf("invalid credentials")
		},
		MaxAuthTries:  cfg.MaxAuthTries,
		ServerVersion: "SSH-2.0-SocksIP",
	}
	sshConfig.AddHostKey(privateKey)

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", cfg.ListenAddr, err)
	}
	defer listener.Close()

	logger.Info("SSH server listening", "addr", cfg.ListenAddr)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // Graceful shutdown
			}
			logger.Error("failed to accept SSH connection", "error", err)
			continue
		}
		go handleConnection(conn, sshConfig, logger, appCfg)
	}
}

func handleConnection(conn net.Conn, sshConfig *ssh.ServerConfig, logger *slog.Logger, appCfg *config.Config) {
	defer conn.Close()
	serverConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		logger.Warn("SSH handshake failed", "remote_addr", conn.RemoteAddr(), "error", err)
		return
	}

	logger.Info("SSH connection established", "user", serverConn.User(), "client_version", string(serverConn.ClientVersion()))
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() == "session" {
			channel, requests, err := newChannel.Accept()
			if err != nil {
				logger.Error("could not accept session channel", "error", err)
				continue
			}
			go ssh.DiscardRequests(requests)
			go io.Copy(io.Discard, channel) // We don't provide a shell
		} else if newChannel.ChannelType() == "direct-tcpip" {
			go handleDirectTCPIP(newChannel, serverConn, logger, appCfg)
		} else {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

func handleDirectTCPIP(newChannel ssh.NewChannel, sconn *ssh.ServerConn, logger *slog.Logger, appCfg *config.Config) {
	type directTCPIPRequest struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}

	var req directTCPIPRequest
	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		logger.Error("failed to unmarshal direct-tcpip request", "error", err)
		newChannel.Reject(ssh.ConnectionFailed, "parse error")
		return
	}

	dest := net.JoinHostPort(req.Host, fmt.Sprintf("%d", req.Port))
	logger.Debug("received direct-tcpip request", "user", sconn.User(), "dest", dest)

	var socksAuth *proxy.Auth
	username, okU := sconn.Permissions.Extensions["username"]
	password, okP := sconn.Permissions.Extensions["password"]
	if okU && okP {
		socksAuth = &proxy.Auth{User: username, Password: password}
	}

	dialer, err := proxy.SOCKS5("tcp", appCfg.SOCKS5.ListenAddr, socksAuth, proxy.Direct)
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
	defer targetConn.Close()

	channel, requests, err := newChannel.Accept()
	if err != nil {
		logger.Error("could not accept direct-tcpip channel", "error", err)
		return
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)

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
	logger.Debug("SSH forwarding connection closed", "user", sconn.User(), "dest", dest)
}

func generateOrLoadHostKey(path string, logger *slog.Logger) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.Info("generating new SSH host key", "path", path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		keyBytes := x509.MarshalPKCS1PrivateKey(key)
		pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
		if err := os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0600); err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(pemBlock), nil
	}
	return os.ReadFile(path)
}

func extractHWID(version string) string {
	// e.g., SSH-2.0-SocksIP_1.0_HWID_ABCDE12345
	parts := strings.Split(version, "_")
	if len(parts) == 4 && parts[2] == "HWID" {
		return parts[3]
	}
	return ""
}
