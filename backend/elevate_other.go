//go:build !windows

package backend

// HandOffIfNotElevated — повышение прав через планировщик есть только в Windows.
func HandOffIfNotElevated() bool { return false }
