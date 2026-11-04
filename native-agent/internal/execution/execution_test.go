package execution

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestExecutionHelper(t *testing.T) {
	if os.Getenv("REAP_EXECUTION_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		os.Exit(99)
	}
	switch args[1] {
	case "streams":
		var wg sync.WaitGroup
		for _, stream := range []*os.File{os.Stdout, os.Stderr} {
			wg.Add(1)
			go func(stream *os.File) {
				defer wg.Done()
				for i := 0; i < 32; i++ {
					stream.Write(bytes.Repeat([]byte("x"), 4096))
				}
			}(stream)
		}
		wg.Wait()
		os.Exit(7)
	case "cap":
		os.Stdout.Write(bytes.Repeat([]byte("x"), OutputLimit+100000))
		time.Sleep(30 * time.Second)
	case "invalid":
		os.Stdout.Write([]byte{'A', 0xff, 'B'})
		os.Stderr.WriteString("雪")
		os.Exit(0)
	case "holder":
		child := exec.Command(os.Args[0], "-test.run=TestExecutionHelper", "--", "sleep")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(98)
		}
		os.WriteFile(args[2], []byte(strconv.Itoa(child.Process.Pid)), 0600)
		fmt.Println("before timeout")
		os.Exit(0)
	case "sleep":
		time.Sleep(30 * time.Second)
	}
	os.Exit(0)
}

func helperCommand(t *testing.T, mode string, args ...string) string {
	t.Helper()
	t.Setenv("REAP_EXECUTION_HELPER", "1")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return `"` + exe + `" -test.run=TestExecutionHelper -- ` + mode + ` ` + strings.Join(args, " ")
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	command := quote(exe) + " -test.run=TestExecutionHelper -- " + mode
	for _, arg := range args {
		command += " " + quote(arg)
	}
	return command
}

func TestSeparateSimultaneousStreamsAndExit(t *testing.T) {
	result, err := Run(context.Background(), helperCommand(t, "streams"), 5)
	if err != nil || result.ExitCode != 7 || len(result.Stdout) != 32*4096 || len(result.Stderr) != 32*4096 {
		t.Fatalf("bad result: code=%d streams=%d/%d error=%v stderr=%q", result.ExitCode, len(result.Stdout), len(result.Stderr), err, result.Stderr[:min(len(result.Stderr), 200)])
	}
}

func TestUnicodeAndInvalidOutput(t *testing.T) {
	result, err := Run(context.Background(), helperCommand(t, "invalid"), 5)
	if err != nil || result.ExitCode != 0 || result.Stdout != "A\ufffdB" || result.Stderr != "雪" {
		t.Fatalf("bad UTF8 result %#v %v", result, err)
	}
	command := "printf '%s' 'quoted path 雪' | cat"
	if runtime.GOOS == "windows" {
		command = `echo "quoted path" | findstr "quoted"`
	}
	result, err = Run(context.Background(), command, 5)
	if err != nil || result.ExitCode != 0 || !strings.Contains(result.Stdout, "quoted path") {
		t.Fatalf("shell quoting/pipe failed %#v %v", result, err)
	}
}

func TestOutputCap(t *testing.T) {
	start := time.Now()
	result, err := Run(context.Background(), helperCommand(t, "cap"), 5)
	if err != nil || result.ExitCode != 125 || len(result.Stdout) != OutputLimit || !strings.Contains(result.Stderr, "output cap reached") || time.Since(start) > 3*time.Second {
		t.Fatalf("unbounded cap: code=%d bytes=%d duration=%v err=%v stderr=%q", result.ExitCode, len(result.Stdout), time.Since(start), err, result.Stderr)
	}
}

func TestBackgroundChildDeadline(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid.txt")
	argument := pidFile
	if runtime.GOOS == "windows" {
		argument = `"` + pidFile + `"`
	}
	start := time.Now()
	result, err := Run(context.Background(), helperCommand(t, "holder", argument), 0.3)
	if err != nil || result.ExitCode != 124 || !strings.Contains(result.Stdout, "before timeout") || !strings.Contains(result.Stderr, "timed out") || time.Since(start) > 3*time.Second {
		t.Fatalf("unbounded retained pipe: %#v %v", result, err)
	}
	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(pidData))
	if err != nil {
		t.Fatal(err)
	}
	if err := assertStopped(pid); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	command := helperCommand(t, "sleep")
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	_, err := Run(ctx, command, 30)
	if err != context.Canceled || time.Since(start) > 3*time.Second {
		t.Fatalf("cancellation failed after %v: %v", time.Since(start), err)
	}
}

func TestUnicodeCommandLimit(t *testing.T) {
	if _, err := Run(context.Background(), strings.Repeat("雪", MaxCommand+1), 1); err == nil {
		t.Fatal("oversized command accepted")
	}
}

func TestAlreadyCanceledCommandDoesNotStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := Run(ctx, helperCommand(t, "sleep"), 30)
	if err != context.Canceled || result.Duration != 0 {
		t.Fatalf("already canceled execution started: %#v %v", result, err)
	}
}
