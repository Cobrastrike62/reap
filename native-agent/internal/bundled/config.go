// Package bundled reads the small connection setup appended to a release agent.
package bundled

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

const Magic = "REAPCFG1"
const MaxSize = 65536
const footerSize int64 = int64(len(Magic)) + 4

var ErrMissing = errors.New("this agent has no saved connection setup; create a ready-to-run agent in Reap with agent create HOST")
var hostLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)

type Config struct {
	Version     int    `json:"version"`
	Connect     string `json:"connect"`
	Port        int    `json:"port"`
	Token       string `json:"token"`
	Fingerprint string `json:"fingerprint"`
}

func (config Config) Validate() error {
	if config.Version != 1 {
		return errors.New("unsupported connection setup version; create a new agent in Reap")
	}
	if config.Connect == "" || len(config.Connect) > 253 || strings.TrimSpace(config.Connect) != config.Connect {
		return errors.New("connection setup has an invalid Reap host")
	}
	if ip := net.ParseIP(config.Connect); ip != nil {
		if ip.IsUnspecified() {
			return errors.New("connection setup must use a reachable Reap host, not 0.0.0.0 or ::")
		}
	} else {
		for _, label := range strings.Split(strings.TrimSuffix(config.Connect, "."), ".") {
			if !hostLabel.MatchString(label) {
				return errors.New("connection setup host must be an IP address or hostname")
			}
		}
	}
	if config.Port < 1 || config.Port > 65535 {
		return errors.New("connection setup port must be between 1 and 65535")
	}
	if !tokenPattern.MatchString(config.Token) {
		return errors.New("connection setup has an invalid authentication token")
	}
	pin, err := hex.DecodeString(config.Fingerprint)
	if err != nil || len(pin) != 32 || strings.ToLower(config.Fingerprint) != config.Fingerprint {
		return errors.New("connection setup has an invalid certificate fingerprint")
	}
	return nil
}

// Read uses a fixed-size footer before allocating the bounded configuration.
// JSON keys are checked individually to reject duplicates as well as unknowns.
func Read(reader io.ReaderAt, size int64) (*Config, error) {
	if size < footerSize {
		return nil, ErrMissing
	}
	footer := make([]byte, footerSize)
	if _, err := reader.ReadAt(footer, size-footerSize); err != nil {
		return nil, fmt.Errorf("read saved connection setup: %w", err)
	}
	if string(footer[:len(Magic)]) != Magic {
		return nil, ErrMissing
	}
	length := int64(binary.BigEndian.Uint32(footer[len(Magic):]))
	if length < 2 || length > MaxSize || length > size-footerSize {
		return nil, errors.New("saved connection setup is damaged (invalid size); create a new agent in Reap")
	}
	data := make([]byte, length)
	if _, err := reader.ReadAt(data, size-footerSize-length); err != nil {
		return nil, fmt.Errorf("read saved connection setup: %w", err)
	}
	if !utf8.Valid(data) {
		return nil, errors.New("saved connection setup is damaged (invalid text); create a new agent in Reap")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("saved connection setup is damaged (expected an object); create a new agent in Reap")
	}
	seen := map[string]bool{}
	allowed := map[string]bool{"version": true, "connect": true, "port": true, "token": true, "fingerprint": true}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return nil, errors.New("saved connection setup is damaged (unknown or repeated field); create a new agent in Reap")
		}
		seen[name] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("saved connection setup is damaged (invalid field); create a new agent in Reap")
		}
	}
	if _, err := decoder.Token(); err != nil || len(seen) != len(allowed) {
		return nil, errors.New("saved connection setup is damaged (missing field); create a new agent in Reap")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("saved connection setup is damaged (extra data); create a new agent in Reap")
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, errors.New("saved connection setup is damaged (wrong field type); create a new agent in Reap")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &config, nil
}

func Load(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open this agent to read connection setup: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("read this agent's size: %w", err)
	}
	return Read(file, info.Size())
}
