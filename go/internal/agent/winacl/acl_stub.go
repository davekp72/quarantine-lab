//go:build !windows

package winacl

import "fmt"

func Protect(path string) error {
	return fmt.Errorf("winacl.Protect requires windows")
}

func RememberGuestControlUser() {}

func CheckProtected(path string) error {
	return fmt.Errorf("winacl.CheckProtected requires windows")
}
