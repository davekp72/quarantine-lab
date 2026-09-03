package registry

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"www.velocidex.com/golang/regparser"
)

// WalkHiveFile parses a REGF hive and appends IndexRecords under prefix.
func WalkHiveFile(hivePath, prefix string, out *[]IndexRecord) (int, error) {
	f, err := os.Open(hivePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	reg, err := regparser.NewRegistry(f)
	if err != nil {
		return 0, err
	}
	root := reg.OpenKey("")
	if root == nil {
		return 0, fmt.Errorf("hive root missing: %s", hivePath)
	}
	before := len(*out)
	walkKeyNode(root, normalizeRegKey(prefix, ""), out)
	return len(*out) - before, nil
}

func walkKeyNode(node *regparser.CM_KEY_NODE, keyPath string, out *[]IndexRecord) {
	if node == nil {
		return
	}
	if shouldSkipRegistryKey(keyPath) {
		return
	}
	for _, val := range node.Values() {
		if val == nil {
			continue
		}
		name := val.ValueName()
		typ := val.TypeString()
		vd := val.ValueData()
		raw, data := valuePayload(vd, typ)
		h := ContentHash(typ, valueForHash(raw, data))
		v, size, keep := ValueForStorage(typ, raw, data)
		rec := IndexRecord{K: keyPath, N: name, T: typ, H: h, Size: size}
		if keep {
			rec.V = v
		}
		*out = append(*out, rec)
	}
	for _, sub := range node.Subkeys() {
		if sub == nil {
			continue
		}
		childName := sub.Name()
		if childName == "" {
			continue
		}
		childPath := keyPath + `\` + childName
		walkKeyNode(sub, childPath, out)
	}
}

func valuePayload(vd *regparser.ValueData, typ string) (any, []byte) {
	if vd == nil {
		return nil, nil
	}
	data := vd.Data
	switch typ {
	case "REG_SZ", "REG_EXPAND_SZ":
		s := vd.String
		if s == "" && len(data) > 0 {
			s = string(data)
		}
		s = trimRegString(s)
		return s, []byte(s)
	case "REG_MULTI_SZ":
		if len(vd.MultiSz) > 0 {
			cleaned := make([]string, 0, len(vd.MultiSz))
			for _, part := range vd.MultiSz {
				part = trimRegString(part)
				if part != "" {
					cleaned = append(cleaned, part)
				}
			}
			joined := strings.Join(cleaned, "\n")
			return cleaned, []byte(joined)
		}
		return nil, data
	case "REG_DWORD", "REG_QWORD":
		return fmt.Sprintf("0x%x", vd.Uint64), data
	default:
		if len(data) == 0 {
			return nil, nil
		}
		return hex.EncodeToString(data), data
	}
}

func trimRegString(s string) string {
	s = strings.TrimRight(s, "\x00")
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return s
}

func valueForHash(raw any, data []byte) any {
	if raw != nil {
		return raw
	}
	if len(data) > 0 {
		return hex.EncodeToString(data)
	}
	return ""
}

// ReadDWORDFromHive reads a REG_DWORD at path\name from a hive file (best-effort).
func ReadDWORDFromHive(hivePath, keyPath, valueName string) (uint32, bool) {
	f, err := os.Open(hivePath)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	reg, err := regparser.NewRegistry(f)
	if err != nil {
		return 0, false
	}
	node := reg.OpenKey(keyPath)
	if node == nil {
		return 0, false
	}
	want := strings.ToLower(valueName)
	for _, val := range node.Values() {
		if strings.ToLower(val.ValueName()) != want {
			continue
		}
		vd := val.ValueData()
		if vd == nil {
			return 0, false
		}
		if len(vd.Data) >= 4 {
			return binary.LittleEndian.Uint32(vd.Data[:4]), true
		}
		return uint32(vd.Uint64), true
	}
	return 0, false
}

func shouldSkipRegistryKey(key string) bool {
	u := strings.ToUpper(key)
	patterns := []string{
		`\IRISSERVICE\CACHE\`,
		`\TASKCACHE\TASKS\{`,
		`\EXPLORER\SESSIONINFO\`,
		`\CONTENTDELIVERYMANAGER\`,
		`\INSTALLSERVICE\STATE`,
		`\VOLATILE ENVIRONMENT\`,
		`\APPCOMPATFLAGS\COMPATIBILITY ASSISTANT\`,
		`\WINDOWS\WINDOWS ERROR REPORTING\`,
	}
	for _, p := range patterns {
		if strings.Contains(u, p) {
			return true
		}
	}
	return false
}
