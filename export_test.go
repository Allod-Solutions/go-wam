//go:build windows

// export_test.go exposes internal seams used exclusively by the test suite.
// It is compiled only when running tests (the _test suffix in the filename
// causes the Go toolchain to include it only in test binaries).

package wam

// WithBackend replaces the global WAM backend with b for the duration of a
// test. Pass nil to restore the real WinRT backend.
func WithBackend(b Backend) {
	if b == nil {
		defaultBackend = &realBackend{}
	} else {
		defaultBackend = b
	}
}
