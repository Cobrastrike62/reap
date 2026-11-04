package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reap/native-agent/internal/bundled"
)

func savedAgent(t *testing.T, config string) string {
	t.Helper()
	data := append([]byte("test executable"), []byte(config)...)
	data = append(data, bundled.Magic...)
	data = binary.BigEndian.AppendUint32(data, uint32(len(config)))
	path := filepath.Join(t.TempDir(), "agent")
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSavedConnectionSetupCannotBeOverriddenByFlags(t *testing.T) {
	config := `{"version":1,"connect":"127.0.0.1","port":7443,"token":"` + strings.Repeat("t", 43) + `","fingerprint":"` + strings.Repeat("a", 64) + `"}`
	path := savedAgent(t, config)
	for _, args := range [][]string{{"--connect", "other"}, {"--bind", "127.0.0.1"}, {"--port", "7444"}, {"--token-file", "other"}} {
		err := runExecutable(context.Background(), args, &bytes.Buffer{}, path)
		if err == nil || !strings.Contains(err.Error(), "run it with no options") {
			t.Fatalf("conflicting options were not rejected: %v", err)
		}
	}
	var output bytes.Buffer
	if err := runExecutable(context.Background(), []string{"--version"}, &output, path); err != nil || !strings.Contains(output.String(), "protocol 1") {
		t.Fatalf("saved agent version failed: %v", err)
	}
	if err := runExecutable(context.Background(), []string{"--help"}, &output, path); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("saved agent help failed: %v", err)
	}
}

func TestMalformedSavedSetupFailsBeforeConnecting(t *testing.T) {
	path := savedAgent(t, `{"version":1,"connect":"127.0.0.1","port":7443,"token":"short","fingerprint":"bad"}`)
	var output bytes.Buffer
	err := runExecutable(context.Background(), nil, &output, path)
	if err == nil || output.Len() != 0 || !strings.Contains(err.Error(), "invalid authentication token") {
		t.Fatalf("invalid setup reached connection: %v %q", err, output.String())
	}
}
