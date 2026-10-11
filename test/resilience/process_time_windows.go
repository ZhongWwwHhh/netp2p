//go:build windows

package resilience

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	getCurrentProcess = kernel32.NewProc("GetCurrentProcess")
	getProcessTimes   = kernel32.NewProc("GetProcessTimes")
)

func processCPUTime() (time.Duration, error) {
	var creation, exit, kernel, user syscall.Filetime
	handle, _, callErr := getCurrentProcess.Call()
	if handle == 0 {
		return 0, callErr
	}
	result, _, callErr := getProcessTimes.Call(
		handle,
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if result == 0 {
		return 0, callErr
	}
	return time.Duration(kernel.Nanoseconds() + user.Nanoseconds()), nil
}
