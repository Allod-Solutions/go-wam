//go:build windows

package wam

import (
	"context"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// asyncStatus mirrors the Windows.Foundation.AsyncStatus enum.
type asyncStatus uint32

const (
	asyncStarted   asyncStatus = 0
	asyncCompleted asyncStatus = 1
	asyncCanceled  asyncStatus = 2
	asyncError     asyncStatus = 3
)

// IAsyncOperation vtable method indices (after IInspectable base).
const (
	// put_Completed(handler) — we don't use this; we poll get_Status instead.
	vtblAsyncPutCompleted = iinspectableBase + 0
	// get_Completed → handler
	vtblAsyncGetCompleted = iinspectableBase + 1
	// GetResults → T
	vtblAsyncGetResults = iinspectableBase + 2
)

// IAsyncInfo (embedded in IAsyncOperation) method indices.
// IAsyncInfo comes before the typed IAsyncOperation<T> methods in the vtable
// because the interface inheritance chain inserts it.
//
// Layout for IAsyncOperation<T>:
//   IUnknown (3) + IInspectable (3) + IAsyncInfo (4) + IAsyncOperation<T> (3)
const (
	vtblAsyncInfoId     = iinspectableBase + 0 // get_Id
	vtblAsyncInfoStatus = iinspectableBase + 1 // get_Status
	vtblAsyncInfoError  = iinspectableBase + 2 // get_ErrorCode
	vtblAsyncInfoCancel = iinspectableBase + 3 // Cancel

	// IAsyncOperation<T> methods follow IAsyncInfo.
	vtblAsyncOpPutCompleted = iinspectableBase + 4
	vtblAsyncOpGetCompleted = iinspectableBase + 5
	vtblAsyncOpGetResults   = iinspectableBase + 6
)

// pollAsync waits for a WinRT IAsyncOperation to complete by polling
// get_Status. Returns the raw vtable pointer to the completed result.
// The caller is responsible for calling comRelease on the op pointer.
//
// We use polling rather than a completion handler to avoid the threading
// complexity of setting up a COM apartment-safe callback from Go.
func pollAsync(ctx context.Context, op unsafe.Pointer) error {
	vtbl := *(*[]uintptr)(unsafe.Pointer(&struct {
		ptr unsafe.Pointer
		len int
		cap int
	}{op, 32, 32}))

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Cancel the operation.
			syscall.SyscallN(vtbl[vtblAsyncInfoCancel], uintptr(op))
			return ctx.Err()
		case <-ticker.C:
			var status asyncStatus
			hr, _, _ := syscall.SyscallN(vtbl[vtblAsyncInfoStatus],
				uintptr(op),
				uintptr(unsafe.Pointer(&status)),
			)
			if hr != 0 {
				return hresultError("IAsyncInfo::get_Status", hr)
			}
			switch status {
			case asyncCompleted:
				return nil
			case asyncError:
				var errCode uintptr
				syscall.SyscallN(vtbl[vtblAsyncInfoError], //nolint:errcheck
					uintptr(op),
					uintptr(unsafe.Pointer(&errCode)),
				)
				return fmt.Errorf("async operation failed: HRESULT 0x%08X", errCode)
			case asyncCanceled:
				return fmt.Errorf("async operation was canceled")
			}
			// asyncStarted — keep polling.
		}
	}
}

// asyncGetResults calls IAsyncOperation<T>::GetResults and returns the
// raw pointer to the result object. The caller must comRelease it.
func asyncGetResults(op unsafe.Pointer) (unsafe.Pointer, error) {
	vtbl := *(*[32]uintptr)(op)
	var result unsafe.Pointer
	hr, _, _ := syscall.SyscallN(vtbl[vtblAsyncOpGetResults],
		uintptr(op),
		uintptr(unsafe.Pointer(&result)),
	)
	if hr != 0 {
		return nil, hresultError("IAsyncOperation::GetResults", hr)
	}
	return result, nil
}
