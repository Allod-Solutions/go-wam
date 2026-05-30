//go:build windows

package wam

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modCombase = windows.NewLazySystemDLL("combase.dll")

	procRoInitialize          = modCombase.NewProc("RoInitialize")
	procRoGetActivationFactory = modCombase.NewProc("RoGetActivationFactory")
	procWindowsCreateString   = modCombase.NewProc("WindowsCreateString")
	procWindowsDeleteString   = modCombase.NewProc("WindowsDeleteString")
	procWindowsGetStringRawBuffer = modCombase.NewProc("WindowsGetStringRawBuffer")
)

const (
	roInitSingleThreaded = 0
	roInitMultiThreaded  = 1
	// S_FALSE means "already initialised on this thread" — not an error.
	sFalse = uintptr(1)
)

var roInitOnce sync.Once

// roInit initialises the Windows Runtime on the calling goroutine's OS thread.
// Idempotent — safe to call multiple times.
func roInit() error {
	var initErr error
	roInitOnce.Do(func() {
		hr, _, _ := procRoInitialize.Call(uintptr(roInitMultiThreaded))
		if hr != 0 && uintptr(hr) != sFalse {
			initErr = fmt.Errorf("RoInitialize: HRESULT 0x%08X", hr)
		}
	})
	return initErr
}

// hstring is an opaque Windows Runtime string handle.
type hstring uintptr

// newHString creates a Windows Runtime HSTRING from a Go string.
// The caller must call hs.delete() when done.
func newHString(s string) (hstring, error) {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return 0, err
	}
	var hs hstring
	hr, _, _ := procWindowsCreateString.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(len([]rune(s))),
		uintptr(unsafe.Pointer(&hs)),
	)
	if hr != 0 {
		return 0, fmt.Errorf("WindowsCreateString: HRESULT 0x%08X", hr)
	}
	return hs, nil
}

func (hs hstring) delete() {
	if hs != 0 {
		procWindowsDeleteString.Call(uintptr(hs)) //nolint:errcheck
	}
}

// String reads the UTF-16 content of an HSTRING back as a Go string.
func (hs hstring) String() string {
	if hs == 0 {
		return ""
	}
	var length uint32
	ptr, _, _ := procWindowsGetStringRawBuffer.Call(
		uintptr(hs),
		uintptr(unsafe.Pointer(&length)),
	)
	if ptr == 0 || length == 0 {
		return ""
	}
	// unsafe.Pointer(ptr): go vet flags uintptr→unsafe.Pointer conversions to
	// protect against GC moving the pointed-to object between the syscall and
	// the conversion. That concern does not apply here: WindowsGetStringRawBuffer
	// returns a pointer into a Windows-owned buffer, not into Go-managed heap.
	// The conversion is therefore safe despite the vet warning.
	return windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), length)) //nolint:unsafeptr
}

// roGetActivationFactory calls RoGetActivationFactory for the given WinRT
// runtime class name and interface IID. Returns the raw vtable pointer.
func roGetActivationFactory(className string, iid *windows.GUID) (unsafe.Pointer, error) {
	hs, err := newHString(className)
	if err != nil {
		return nil, err
	}
	defer hs.delete()

	var factory unsafe.Pointer
	hr, _, _ := procRoGetActivationFactory.Call(
		uintptr(hs),
		uintptr(unsafe.Pointer(iid)),
		uintptr(unsafe.Pointer(&factory)),
	)
	if hr != 0 {
		return nil, fmt.Errorf("RoGetActivationFactory(%s): HRESULT 0x%08X", className, hr)
	}
	return factory, nil
}

// comRelease calls IUnknown::Release on a COM/WinRT object pointer.
func comRelease(p unsafe.Pointer) {
	if p == nil {
		return
	}
	// IUnknown vtable: [QueryInterface, AddRef, Release]
	vtbl := *(*[3]uintptr)(p)
	syscall.SyscallN(vtbl[2], uintptr(p))
}

// hresultError converts a non-zero HRESULT to a Go error.
func hresultError(name string, hr uintptr) error {
	if hr == 0 {
		return nil
	}
	return fmt.Errorf("%s: HRESULT 0x%08X", name, hr)
}
