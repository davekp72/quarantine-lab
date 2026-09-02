package jsonutil

import "testing"

func TestStripBOM(t *testing.T) {
	bom := []byte{0xEF, 0xBB, 0xBF}
	payload := []byte(`{"a":1}`)
	withBOM := append(append([]byte{}, bom...), payload...)
	if got := StripBOM(withBOM); string(got) != `{"a":1}` {
		t.Fatalf("StripBOM: got %q", got)
	}
	var v map[string]any
	if err := Unmarshal(withBOM, &v); err != nil {
		t.Fatal(err)
	}
	if v["a"].(float64) != 1 {
		t.Fatalf("unexpected: %v", v)
	}
}
