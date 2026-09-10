//go:build !windows

package collectors

func usnEventPath(volume, fileName, fileRef, parentRef string) string {
	_ = volume
	_ = fileRef
	_ = parentRef
	return resolveUsnPathFallback(fileName)
}

func BeginPathResolveBudget(n int) func() {
	_ = n
	return func() {}
}
