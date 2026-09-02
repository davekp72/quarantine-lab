//go:build !windows

package collectors

func usnEventPath(volume, fileName, fileRef string) string {
	return resolveUsnPath(fileName)
}

func BeginPathResolveBudget(n int) func() {
	return func() {}
}

func isLeafOnlyPath(p string) bool {
	return false
}
