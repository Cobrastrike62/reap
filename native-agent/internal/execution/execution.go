// Package execution runs one shell command with bounded capture and tree cleanup.
package execution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const OutputLimit = 512 * 1024
const MaxCommand = 256 * 1024

type Result struct {
	Stdout   string  `json:"stdout"`
	Stderr   string  `json:"stderr"`
	ExitCode int     `json:"exit_code"`
	Duration float64 `json:"duration"`
}

type process interface {
	Wait() (int, error)
	Kill() error
	Close() error
}

func Run(ctx context.Context, command string, timeout float64) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if utf8.RuneCountInString(command) > MaxCommand {
		return Result{}, errors.New("command exceeds 256 Ki Unicode code points")
	}
	if math.IsNaN(timeout) || math.IsInf(timeout, 0) {
		return Result{}, errors.New("invalid command timeout")
	}
	timeout = math.Max(0.1, math.Min(timeout, 300))
	start := time.Now()
	commandCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout*float64(time.Second)))
	defer cancel()
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return Result{}, err
	}
	defer stdoutR.Close()
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		stdoutW.Close()
		return Result{}, err
	}
	defer stderrR.Close()
	proc, err := startProcess(command, stdoutW, stderrW)
	stdoutW.Close()
	stderrW.Close()
	if err != nil {
		return Result{Stderr: "Reap agent: cannot start shell command: " + err.Error(), ExitCode: 126, Duration: time.Since(start).Seconds()}, nil
	}
	defer proc.Close()
	capped := make(chan struct{})
	var capOnce sync.Once
	outputs := [2][]byte{}
	var readers sync.WaitGroup
	for i, stream := range []*os.File{stdoutR, stderrR} {
		readers.Add(1)
		go func(i int, stream io.Reader) {
			defer readers.Done()
			buffer := make([]byte, 8192)
			for {
				n, readErr := stream.Read(buffer)
				remaining := OutputLimit - len(outputs[i])
				if n > remaining {
					outputs[i] = append(outputs[i], buffer[:remaining]...)
					capOnce.Do(func() { close(capped) })
				} else {
					outputs[i] = append(outputs[i], buffer[:n]...)
				}
				if readErr != nil {
					return
				}
			}
		}(i, stream)
	}
	readDone := make(chan struct{})
	go func() { readers.Wait(); close(readDone) }()
	type waited struct {
		code int
		err  error
	}
	waitDone := make(chan waited, 1)
	go func() { code, waitErr := proc.Wait(); waitDone <- waited{code, waitErr} }()
	var waitResult waited
	haveWait, haveReads := false, false
	status := -1
	for !haveWait || !haveReads {
		select {
		case <-capped:
			status = 125
		case <-commandCtx.Done():
			status = 124
		case waitResult = <-waitDone:
			haveWait = true
			waitDone = nil
		case <-readDone:
			haveReads = true
			readDone = nil
		}
		if status != -1 {
			break
		}
	}
	// Even an exited shell can leave children holding inherited pipes or running
	// in the background. Kill the entire process group/job before releasing it.
	cleanupErr := proc.Kill()
	if !haveWait {
		select {
		case waitResult = <-waitDone:
			haveWait = true
		case <-time.After(2 * time.Second):
			cleanupErr = errors.Join(cleanupErr, errors.New("process did not exit after cleanup"))
		}
	}
	if !haveReads {
		// Pipe ownership stays here, so escaped descendants cannot extend a deadline.
		select {
		case <-readDone:
		case <-time.After(250 * time.Millisecond):
			stdoutR.Close()
			stderrR.Close()
			<-readDone
		}
	}
	// A cap event may race with normal process/read completion.
	select {
	case <-capped:
		status = 125
	default:
	}
	result := Result{Stdout: strings.ToValidUTF8(string(outputs[0]), "\ufffd"), Stderr: strings.ToValidUTF8(string(outputs[1]), "\ufffd"), ExitCode: waitResult.code, Duration: time.Since(start).Seconds()}
	if status == 124 {
		result.ExitCode = 124
		result.Stderr += "\nReap agent: command timed out; output may be partial."
	}
	if status == 125 {
		result.ExitCode = 125
		result.Stderr += "\nReap agent: output cap reached (512 KiB per stream); command stopped."
	}
	if cleanupErr != nil {
		result.Stderr += "\nReap agent: command-tree cleanup failed: " + cleanupErr.Error()
		if status == 125 {
			result.Stderr = strings.Replace(result.Stderr, "; command stopped.", "; command termination was requested.", 1)
		}
		if result.ExitCode == 0 {
			result.ExitCode = 126
		}
	}
	if waitResult.err != nil && result.ExitCode == 0 {
		result.ExitCode = 126
		result.Stderr += fmt.Sprintf("\nReap agent: process wait failed: %v", waitResult.err)
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, nil
}
