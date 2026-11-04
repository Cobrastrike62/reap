// Reap's foreground, single-session native lab agent.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"reap/native-agent/internal/bundled"
	"reap/native-agent/internal/execution"
	"reap/native-agent/internal/probe"
	"reap/native-agent/internal/protocol"
)

// Set by the repeatable release build, without embedding credentials.
var version = "development"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "Reap agent:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find this agent's connection setup: %w", err)
	}
	return runExecutable(ctx, args, out, executable)
}

func runExecutable(ctx context.Context, args []string, out io.Writer, executable string) error {
	flags := flag.NewFlagSet("reap-agent", flag.ContinueOnError)
	flags.SetOutput(out)
	connect := flags.String("connect", "", "connect back to Reap at HOST")
	bind := flags.String("bind", "", "listen at ADDRESS for one authenticated session (60 seconds)")
	port := flags.Int("port", 0, "TCP port (1-65535)")
	tokenPath := flags.String("token-file", "", "private token file (at least 32 characters)")
	pinPath := flags.String("fingerprint-file", "", "SHA-256 certificate fingerprint file (connect mode)")
	certPath := flags.String("cert", "", "TLS certificate PEM (bind mode)")
	keyPath := flags.String("key", "", "TLS private key PEM (bind mode)")
	showVersion := flags.Bool("version", false, "print build version and exit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Fprintf(out, "reap-agent %s (%s/%s; protocol 1)\n", version, runtime.GOOS, runtime.GOARCH)
		return nil
	}
	config, err := bundled.Load(executable)
	if err != nil && !errors.Is(err, bundled.ErrMissing) {
		return err
	}
	if config != nil {
		if len(args) != 0 {
			return errors.New("this agent already has its connection setup; run it with no options, or create a new agent in Reap to change the host or port")
		}
		address := net.JoinHostPort(config.Connect, strconv.Itoa(config.Port))
		fmt.Fprintf(out, "Connecting to Reap at %s...\n", address)
		channel, err := protocol.Connect(ctx, address, config.Fingerprint, config.Token)
		if err != nil {
			return fmt.Errorf("could not connect to Reap at %s; start agent listen in Reap, then run this file again: %w", address, err)
		}
		defer channel.Close()
		fmt.Fprintln(out, "Connected to Reap. Keep this window open; Ctrl-C disconnects.")
		return serve(ctx, channel)
	}
	if len(args) == 0 {
		return bundled.ErrMissing
	}
	if flags.NArg() != 0 || (*connect == "") == (*bind == "") {
		return errors.New("select exactly one of --connect HOST and --bind ADDRESS")
	}
	if *port < 1 || *port > 65535 {
		return errors.New("--port must be between 1 and 65535")
	}
	if *tokenPath == "" {
		return errors.New("--token-file is required")
	}
	token, err := protocol.TokenFrom(*tokenPath)
	if err != nil {
		return err
	}
	var channel net.Conn
	if *connect != "" {
		if *pinPath == "" {
			return errors.New("--connect requires --fingerprint-file")
		}
		pin, err := os.ReadFile(*pinPath)
		if err != nil {
			return fmt.Errorf("read certificate fingerprint file: %w", err)
		}
		channel, err = protocol.Connect(ctx, net.JoinHostPort(*connect, strconv.Itoa(*port)), string(pin), token)
		if err != nil {
			return err
		}
	} else {
		if *certPath == "" || *keyPath == "" {
			return errors.New("--bind requires --cert and --key")
		}
		certificate, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			return fmt.Errorf("load TLS certificate and private key: %w", err)
		}
		listener, err := net.Listen("tcp", net.JoinHostPort(*bind, strconv.Itoa(*port)))
		if err != nil {
			return fmt.Errorf("listen (check address, port and permissions): %w", err)
		}
		fmt.Fprintf(out, "Reap agent listening on %s for 60 seconds\n", listener.Addr())
		channel, err = protocol.AcceptAuthenticated(ctx, listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}, token, 60*time.Second)
		if err != nil {
			return err
		}
	}
	defer channel.Close()
	fmt.Fprintln(out, "Reap agent connected; Ctrl-C stops it. No persistence is installed.")
	return serve(ctx, channel)
}

func serve(ctx context.Context, channel net.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { channel.Close() })
	defer stop()
	requests := make(chan protocol.Message)
	readErr := make(chan error, 1)
	// Read ahead by at most one request to observe peer EOF while a command runs.
	// Execution and responses stay serialized on this goroutine.
	go func() {
		defer close(requests)
		for {
			message, err := protocol.Read(channel)
			if err != nil {
				readErr <- err
				cancel()
				return
			}
			select {
			case requests <- message:
			case <-ctx.Done():
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			select {
			case err := <-readErr:
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			default:
				return ctx.Err()
			}
		case request, ok := <-requests:
			if !ok {
				return ctx.Err()
			}
			if request["op"] == "close" {
				return nil
			}
			id, err := protocol.ID(request)
			if err != nil {
				return err
			}
			var response protocol.Message
			switch request["op"] {
			case "ping":
				response = protocol.Message{"id": id, "op": "pong"}
			case "exec":
				command, ok := request["command"].(string)
				if !ok {
					return errors.New("exec command must be a string")
				}
				timeout := 30.0
				if value, exists := request["timeout"]; exists {
					number, ok := value.(json.Number)
					if !ok {
						return errors.New("exec timeout must be numeric")
					}
					timeout, err = number.Float64()
					if err != nil || math.IsInf(timeout, 0) || math.IsNaN(timeout) {
						return errors.New("invalid exec timeout")
					}
				}
				result, err := execution.Run(ctx, command, timeout)
				if err != nil {
					return err
				}
				response = protocol.Message{"id": id, "op": "result", "stdout": result.Stdout, "stderr": result.Stderr, "exit_code": result.ExitCode, "duration": result.Duration}
			case "probe_tcp":
				if runtime.GOOS != "linux" {
					return errors.New("native TCP probing is supported only on Linux")
				}
				endpoints, err := json.Marshal(request["endpoints"])
				if err != nil {
					return err
				}
				started := time.Now()
				rows, err := probe.Run(ctx, endpoints)
				if err != nil {
					return err
				}
				response = protocol.Message{"id": id, "op": "probe_result", "rows": rows, "duration": time.Since(started).Seconds()}
			default:
				return errors.New("unsupported agent operation")
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			channel.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := protocol.Write(channel, response); err != nil {
				cancel()
				return err
			}
			channel.SetWriteDeadline(time.Time{})
		}
	}
}
