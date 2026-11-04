package protocol

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

func TokenFrom(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}
	if !utf8.Valid(data) {
		return "", errors.New("token file is not UTF-8")
	}
	token := strings.TrimSpace(string(data))
	if utf8.RuneCountInString(token) < 32 {
		return "", errors.New("token file must contain at least 32 characters")
	}
	return token, nil
}

func Metadata() Message {
	hostname, _ := os.Hostname()
	platform := "Linux"
	if runtime.GOOS == "windows" {
		platform = "Windows"
	}
	message := Message{"version": 1, "platform": platform, "hostname": hostname}
	if runtime.GOOS == "linux" {
		message["capabilities"] = []string{"probe_tcp_v1"}
	}
	return message
}

func validVersion(message Message) bool {
	n, ok := message["version"].(json.Number)
	return ok && n.String() == "1"
}

func AuthenticateClient(channel net.Conn, token string) error {
	message := Metadata()
	message["op"], message["token"] = "auth", token
	if err := Write(channel, message); err != nil {
		return err
	}
	reply, err := Read(channel)
	if err != nil {
		return err
	}
	if reply["op"] != "ready" || !validVersion(reply) {
		return errors.New("agent authentication failed")
	}
	return nil
}

func AuthenticateServer(channel net.Conn, token string) error {
	hello, err := Read(channel)
	if err != nil {
		return err
	}
	supplied, ok := hello["token"].(string)
	if !ok || hello["op"] != "auth" || !validVersion(hello) || subtle.ConstantTimeCompare([]byte(supplied), []byte(token)) != 1 {
		return errors.New("agent authentication failed")
	}
	message := Metadata()
	message["op"] = "ready"
	return Write(channel, message)
}

// PinnedConfig replaces CA/hostname validation with a mandatory leaf DER pin.
// VerifyConnection runs for every TLS connection before any token is sent.
func PinnedConfig(fingerprint string) (*tls.Config, error) {
	pin, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(fingerprint), ":", ""))
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("a SHA-256 certificate fingerprint is required")
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // Explicit pin verification below is mandatory.
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("server did not send a certificate")
			}
			digest := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(digest[:], pin) != 1 {
				return errors.New("agent certificate fingerprint mismatch")
			}
			return nil
		},
	}, nil
}

func Connect(ctx context.Context, address, fingerprint, token string) (net.Conn, error) {
	config, err := PinnedConfig(fingerprint)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	channel, err := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 30 * time.Second}, Config: config}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("TLS connect (check host, port and certificate pin): %w", err)
	}
	stop := context.AfterFunc(ctx, func() { channel.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	channel.SetDeadline(deadline)
	if err := AuthenticateClient(channel, token); err != nil {
		channel.Close()
		return nil, err
	}
	channel.SetDeadline(time.Time{})
	return channel, nil
}

// AcceptAuthenticated enforces a single absolute window across all attempts.
func AcceptAuthenticated(ctx context.Context, listener net.Listener, config *tls.Config, token string, window time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	defer listener.Close()
	deadline, _ := ctx.Deadline()
	for attempt := 0; attempt < 64; attempt++ {
		raw, err := listener.Accept()
		if err != nil {
			return nil, fmt.Errorf("no authenticated agent connection received: %w", err)
		}
		perAttempt := time.Now().Add(10 * time.Second)
		if deadline.Before(perAttempt) {
			perAttempt = deadline
		}
		raw.SetDeadline(perAttempt)
		channel := tls.Server(raw, config)
		closeOnCancel := context.AfterFunc(ctx, func() { channel.Close() })
		err = channel.HandshakeContext(ctx)
		if err == nil {
			err = AuthenticateServer(channel, token)
		}
		closeOnCancel()
		if err == nil && ctx.Err() == nil {
			channel.SetDeadline(time.Time{})
			return channel, nil
		}
		channel.Close()
		if ctx.Err() != nil {
			return nil, errors.New("no authenticated agent connection received before listener deadline")
		}
	}
	return nil, errors.New("authenticated listener handshake attempt limit reached")
}
