//go:build linux

package execution

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

type linuxProcess struct{ cmd *exec.Cmd }

func startProcess(command string, stdout, stderr *os.File) (process, error) {
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("/bin/sh must exist and permit execution: %w", err)
	}
	return &linuxProcess{cmd}, nil
}

func (p *linuxProcess) Wait() (int, error) {
	err := p.cmd.Wait()
	if _, ok := err.(*exec.ExitError); ok {
		if status, ok := p.cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return -int(status.Signal()), nil
		}
		return p.cmd.ProcessState.ExitCode(), nil
	}
	if err != nil {
		return 126, err
	}
	return p.cmd.ProcessState.ExitCode(), nil
}

func (p *linuxProcess) Kill() error {
	err := syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}
func (p *linuxProcess) Close() error { return nil }
