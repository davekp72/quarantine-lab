//go:build !windows

package privileges

func EnableManifestRead() error { return nil }
