package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"reap/native-agent/internal/execution"
	"reap/native-agent/internal/protocol"
)

func TestAgentCommandHelper(t *testing.T) {
	if os.Getenv("REAP_MAIN_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		os.Exit(99)
	}
	if args[1] == "cap" {
		os.Stdout.Write(bytes.Repeat([]byte("a"), execution.OutputLimit+100))
		time.Sleep(10 * time.Second)
	}
	if args[1] == "sleep" {
		time.Sleep(30 * time.Second)
	}
	os.Exit(0)
}

func commandHelper(t *testing.T, mode string) string {
	t.Helper()
	t.Setenv("REAP_MAIN_HELPER", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return `"` + executable + `" -test.run=TestAgentCommandHelper -- ` + mode
	}
	return "'" + strings.ReplaceAll(executable, "'", "'\"'\"'") + "' -test.run=TestAgentCommandHelper -- " + mode
}

func session(t *testing.T) (net.Conn, <-chan error) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { defer server.Close(); done <- serve(context.Background(), server) }()
	t.Cleanup(func() { client.Close() })
	client.SetDeadline(time.Now().Add(8 * time.Second))
	return client, done
}

func exchange(t *testing.T, channel net.Conn, request protocol.Message) protocol.Message {
	t.Helper()
	if err := protocol.Write(channel, request); err != nil {
		t.Fatal(err)
	}
	response, err := protocol.Read(channel)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func closeSession(t *testing.T, channel net.Conn, done <-chan error) {
	t.Helper()
	if err := protocol.Write(channel, protocol.Message{"op": "close"}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSessionKeepsIntegerIDsAndSerializesResults(t *testing.T) {
	channel, done := session(t)
	id := json.Number("922337203685477580812345")
	response := exchange(t, channel, protocol.Message{"id": id, "op": "ping"})
	if response["id"] != id || response["op"] != "pong" {
		t.Fatalf("bad pong %#v", response)
	}
	command := `printf out; printf err >&2; exit 7`
	if runtime.GOOS == "windows" {
		command = `echo out & echo err 1>&2 & exit /b 7`
	}
	response = exchange(t, channel, protocol.Message{"id": 2, "op": "exec", "command": command, "timeout": 2})
	if response["id"] != json.Number("2") || response["op"] != "result" || response["exit_code"] != json.Number("7") || !strings.Contains(response["stdout"].(string), "out") || !strings.Contains(response["stderr"].(string), "err") {
		t.Fatalf("bad exec %#v", response)
	}
	closeSession(t, channel, done)
}

func TestSessionSurvivesCommandTimeoutAndOutputCap(t *testing.T) {
	channel, done := session(t)
	for i, mode := range []string{"sleep", "cap"} {
		timeout := 2.0
		code := "125"
		if mode == "sleep" {
			timeout = 0.1
			code = "124"
		}
		response := exchange(t, channel, protocol.Message{"id": i*2 + 1, "op": "exec", "command": commandHelper(t, mode), "timeout": timeout})
		if response["exit_code"] != json.Number(code) {
			t.Fatalf("bad %s response %#v", mode, response)
		}
		pong := exchange(t, channel, protocol.Message{"id": i*2 + 2, "op": "ping"})
		if pong["op"] != "pong" {
			t.Fatal("channel failed after bounded command")
		}
	}
	closeSession(t, channel, done)
}

func TestTransportFailureCancelsActiveCommand(t *testing.T) {
	channel, done := session(t)
	if err := protocol.Write(channel, protocol.Message{"id": 1, "op": "exec", "command": commandHelper(t, "sleep"), "timeout": 30}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	channel.Close()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("active command survived peer EOF")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("EOF cleanup exceeded bound")
	}
}

func TestMalformedRequestsCloseSession(t *testing.T) {
	for _, request := range []protocol.Message{
		{"id": 1.5, "op": "ping"},
		{"id": 1, "op": "unknown"},
		{"id": 1, "op": "exec", "command": []string{"bad"}},
		{"id": 1, "op": "exec", "command": "echo bad", "timeout": "30"},
		{"id": 1, "op": "probe_tcp", "endpoints": []any{map[string]any{"proto": "udp", "ip": "127.0.0.1", "port": 3000, "addr": "127.0.0.1:3000"}}},
	} {
		channel, done := session(t)
		if err := protocol.Write(channel, request); err != nil {
			t.Fatal(err)
		}
		if _, err := protocol.Read(channel); err == nil {
			t.Fatal("malformed request received a response")
		}
		if err := <-done; err == nil {
			t.Fatal("malformed request was not rejected")
		}
		channel.Close()
	}
}

func TestCLIValidationAndVersion(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), []string{"--version"}, &output); err != nil || !strings.Contains(output.String(), "protocol 1") {
		t.Fatalf("version failed: %v %s", err, &output)
	}
	for _, args := range [][]string{{}, {"--connect", "127.0.0.1", "--bind", "127.0.0.1"}, {"--connect", "127.0.0.1", "--port", "0"}, {"--bind", "127.0.0.1", "--port", "3000"}} {
		if err := run(context.Background(), args, io.Discard); err == nil {
			t.Fatal(fmt.Sprintf("accepted invalid args %q", args))
		}
	}
}
