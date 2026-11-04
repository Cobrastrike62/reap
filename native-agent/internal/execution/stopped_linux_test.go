//go:build linux

package execution

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

func assertStopped(pid int) error {
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) == syscall.ESRCH {
			return nil
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if os.IsNotExist(err) {
			return nil
		}
		// An orphan can briefly remain a zombie until the namespace init reaps it.
		if index := strings.LastIndex(string(data), ")"); index >= 0 && strings.HasPrefix(string(data)[index+1:], " Z ") {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("child %d still running after command cleanup", pid)
}
