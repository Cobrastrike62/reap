//go:build windows

package execution

import (
	"fmt"
	"syscall"
)

func assertStopped(pid int) error {
	handle, err := syscall.OpenProcess(0x1000|syscall.SYNCHRONIZE, false, uint32(pid))
	if err == syscall.Errno(87) { // ERROR_INVALID_PARAMETER: PID no longer exists.
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect child %d after job cleanup: %w", pid, err)
	}
	defer syscall.CloseHandle(handle)
	state, err := syscall.WaitForSingleObject(handle, 1000)
	if err != nil {
		return err
	}
	if state != syscall.WAIT_OBJECT_0 {
		return fmt.Errorf("child %d still running after job cleanup", pid)
	}
	return nil
}
