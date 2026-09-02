package vbox

import "testing"

func TestVMSessionActive(t *testing.T) {
	if !vmSessionActive("running") || !vmSessionActive("paused") {
		t.Fatal("expected active")
	}
	if vmSessionActive("poweroff") || vmSessionActive("") {
		t.Fatal("expected inactive")
	}
}

func TestIgnoreNatPFMissing(t *testing.T) {
	if ignoreNatPFMissing(nil) != nil {
		t.Fatal("nil should pass")
	}
	err := ignoreNatPFMissing(&fakeError{"could not find NAT rule foo"})
	if err != nil {
		t.Fatalf("expected ignore: %v", err)
	}
	err = ignoreNatPFMissing(&fakeError{"some other failure"})
	if err == nil {
		t.Fatal("expected real error")
	}
}

type fakeError struct{ s string }

func (e *fakeError) Error() string { return e.s }
