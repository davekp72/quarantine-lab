package jsonutil

import (
	"bytes"
	"encoding/json"
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// StripBOM removes a leading UTF-8 byte order mark from PowerShell-written JSON files.
func StripBOM(b []byte) []byte {
	return bytes.TrimPrefix(b, utf8BOM)
}

// Unmarshal decodes JSON, tolerating a UTF-8 BOM prefix.
func Unmarshal(data []byte, v any) error {
	return json.Unmarshal(StripBOM(data), v)
}
