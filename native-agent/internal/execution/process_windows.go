//go:build windows

package execution

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var createJobObject = kernel32.NewProc("CreateJobObjectW")
var setJobInformation = kernel32.NewProc("SetInformationJobObject")
var assignProcessToJob = kernel32.NewProc("AssignProcessToJobObject")
var terminateJob = kernel32.NewProc("TerminateJobObject")
var resumeThread = kernel32.NewProc("ResumeThread")

type basicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}
type extendedLimitInformation struct {
	BasicLimitInformation basicLimitInformation
	IOCounters            [6]uint64
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}
type windowsProcess struct{ handle, waitHandle, job syscall.Handle }

func startProcess(command string, stdout, stderr *os.File) (process, error) {
	job, _, callErr := createJobObject.Call(0, 0)
	if job == 0 {
		return nil, fmt.Errorf("create Windows Job Object: %w", callErr)
	}
	keepJob := false
	defer func() {
		if !keepJob {
			syscall.CloseHandle(syscall.Handle(job))
		}
	}()
	limits := extendedLimitInformation{}
	limits.BasicLimitInformation.LimitFlags = 0x2000 // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	ok, _, callErr := setJobInformation.Call(job, 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	if ok == 0 {
		return nil, fmt.Errorf("configure Windows Job Object: %w", callErr)
	}
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		return nil, err
	}
	defer stdin.Close()
	for _, file := range []*os.File{stdin, stdout, stderr} {
		if err := syscall.SetHandleInformation(syscall.Handle(file.Fd()), syscall.HANDLE_FLAG_INHERIT, syscall.HANDLE_FLAG_INHERIT); err != nil {
			return nil, err
		}
		defer syscall.SetHandleInformation(syscall.Handle(file.Fd()), syscall.HANDLE_FLAG_INHERIT, 0)
	}
	root := os.Getenv("SystemRoot")
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("SystemRoot must identify an absolute Windows installation path")
	}
	shell := filepath.Join(root, "System32", "cmd.exe")
	application, err := syscall.UTF16PtrFromString(shell)
	if err != nil {
		return nil, err
	}
	// /s /c strips the outer pair of quotes while preserving the command itself.
	line, err := syscall.UTF16PtrFromString(`"` + shell + `" /d /s /c "` + command + `"`)
	if err != nil {
		return nil, err
	}
	startup := syscall.StartupInfo{Cb: uint32(unsafe.Sizeof(syscall.StartupInfo{})), Flags: syscall.STARTF_USESTDHANDLES, StdInput: syscall.Handle(stdin.Fd()), StdOutput: syscall.Handle(stdout.Fd()), StdErr: syscall.Handle(stderr.Fd())}
	var info syscall.ProcessInformation
	// The primary thread remains suspended until job assignment succeeds: no
	// command or child can execute outside the job during a launch/assign race.
	err = syscall.CreateProcess(application, line, nil, nil, true, 0x4|0x400|0x08000000, nil, nil, &startup, &info)
	if err != nil {
		return nil, fmt.Errorf("execute %s (check shell availability and execution permissions): %w", shell, err)
	}
	defer syscall.CloseHandle(info.Thread)
	cleanup := func() {
		syscall.TerminateProcess(info.Process, 126)
		syscall.WaitForSingleObject(info.Process, 2000)
		syscall.CloseHandle(info.Process)
	}
	ok, _, callErr = assignProcessToJob.Call(job, uintptr(info.Process))
	if ok == 0 {
		cleanup()
		return nil, fmt.Errorf("assign suspended command to Windows Job Object (parent job may restrict nesting): %w", callErr)
	}
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("get current process for Windows wait handle: %w", err)
	}
	var waitHandle syscall.Handle
	if err := syscall.DuplicateHandle(current, info.Process, current, &waitHandle, 0, false, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		cleanup()
		return nil, fmt.Errorf("create Windows process wait handle: %w", err)
	}
	resumed, _, callErr := resumeThread.Call(uintptr(info.Thread))
	if resumed == 0xffffffff {
		syscall.CloseHandle(waitHandle)
		cleanup()
		return nil, fmt.Errorf("resume Windows command: %w", callErr)
	}
	keepJob = true
	return &windowsProcess{info.Process, waitHandle, syscall.Handle(job)}, nil
}

func (p *windowsProcess) Wait() (int, error) {
	// Own a distinct handle so bounded cleanup may close the original even if
	// an exceptional kernel/termination failure leaves this wait outstanding.
	defer syscall.CloseHandle(p.waitHandle)
	if _, err := syscall.WaitForSingleObject(p.waitHandle, syscall.INFINITE); err != nil {
		return 126, err
	}
	var code uint32
	if err := syscall.GetExitCodeProcess(p.waitHandle, &code); err != nil {
		return 126, err
	}
	return int(code), nil
}
func (p *windowsProcess) Kill() error {
	ok, _, err := terminateJob.Call(uintptr(p.job), 1)
	if ok == 0 {
		return fmt.Errorf("terminate Windows command job: %w", err)
	}
	return nil
}
func (p *windowsProcess) Close() error {
	jobErr := syscall.CloseHandle(p.job)
	processErr := syscall.CloseHandle(p.handle)
	if jobErr != nil {
		return jobErr
	}
	return processErr
}
