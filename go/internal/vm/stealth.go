package vm

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/vbox"
)

// ApplyStealth applies host-side VirtualBox fingerprint softening while the VM is powered off.
// Does not change the graphics controller (VBoxSVGA). Guest Additions are optional.
func (s *Service) ApplyStealth() (string, error) {
	st := s.Cfg.Isolation.Stealth
	if st.Enabled != nil && !*st.Enabled {
		return "stealth disabled in config", nil
	}

	state, err := s.VBox.VMState(s.Cfg.VMName)
	if err != nil {
		return "", err
	}
	switch strings.ToLower(state) {
	case "running", "paused", "starting":
		return "", fmt.Errorf("VM is %s; power off before applying stealth (DMI/MAC/CPU)", state)
	case "saved":
		return "", fmt.Errorf("VM has saved state; discard saved state or power off cleanly before stealth")
	}

	var notes []string
	fw, _ := firmwareType(s.VBox, s.Cfg.VMName)
	cpu := strings.TrimSpace(st.CPUProfile)
	if cpu == "" {
		cpu = "Intel Core i7-6700K"
	}
	// EFI + a named VBox CPU profile (Skylake etc.) triple-faults Win11 Setup/boot.
	if strings.EqualFold(fw, "efi") {
		if err := s.VBox.ModifyVM(s.Cfg.VMName, "cpu-profile", "host"); err != nil {
			return "", fmt.Errorf("cpu-profile host (EFI): %w", err)
		}
		notes = append(notes, "cpu-profile=host (EFI)")
	} else if !strings.EqualFold(cpu, "host") && !strings.EqualFold(cpu, "none") {
		if err := s.VBox.ModifyVM(s.Cfg.VMName, "cpu-profile", cpu); err != nil {
			return "", fmt.Errorf("cpu-profile: %w", err)
		}
		notes = append(notes, "cpu-profile="+cpu)
	}

	if p := strings.TrimSpace(st.ParavirtProvider); p != "" {
		if err := s.VBox.ModifyVM(s.Cfg.VMName, "paravirtprovider", p); err != nil {
			return "", fmt.Errorf("paravirtprovider: %w", err)
		}
		notes = append(notes, "paravirt="+p)
	}

	mac, generated, err := resolveStealthMAC(s.VBox, s.Cfg.VMName, st)
	if err != nil {
		return "", err
	}
	if err := s.VBox.ModifyVM(s.Cfg.VMName, "macaddress1", mac); err != nil {
		return "", fmt.Errorf("macaddress1: %w", err)
	}
	notes = append(notes, "mac="+formatMAC(mac))
	if generated && s.ConfigPath != "" {
		if err := persistStealthMAC(s.ConfigPath, mac); err != nil {
			notes = append(notes, "mac-persist-warn="+err.Error())
		} else {
			notes = append(notes, "mac persisted to config")
		}
	}

	if strings.EqualFold(fw, "efi") {
		// Any pcbios/0/Config/* on EFI replaces CFGM and drops BootDevice0
		// (VERR_CFGM_VALUE_NOT_FOUND on start). Clear leftovers; keep ACPI only.
		_ = clearPcbiosConfigExtra(s.VBox, s.Cfg.VMName)
		notes = append(notes, "acpi spoofed (EFI — pcbios DMI skipped)")
	} else {
		// Legacy BIOS: setting any pcbios Config key requires BootDevice*.
		_ = s.VBox.SetExtraData(s.Cfg.VMName, "VBoxInternal/Devices/pcbios/0/Config/BootDevice0", "IDE")
		_ = s.VBox.SetExtraData(s.Cfg.VMName, "VBoxInternal/Devices/pcbios/0/Config/BootDevice1", "DVD")
		_ = s.VBox.SetExtraData(s.Cfg.VMName, "VBoxInternal/Devices/pcbios/0/Config/BootDevice2", "NONE")
		_ = s.VBox.SetExtraData(s.Cfg.VMName, "VBoxInternal/Devices/pcbios/0/Config/BootDevice3", "NONE")
		for key, val := range defaultDMI(st.DMI) {
			full := "VBoxInternal/Devices/pcbios/0/Config/" + key
			if err := s.VBox.SetExtraData(s.Cfg.VMName, full, val); err != nil {
				return "", fmt.Errorf("setextradata %s: %w", key, err)
			}
		}
		_ = s.VBox.SetExtraData(s.Cfg.VMName, "VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxVer", " ")
		_ = s.VBox.SetExtraData(s.Cfg.VMName, "VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxRev", " ")
		notes = append(notes, "pcbios DMI + acpi spoofed")
	}
	_ = s.VBox.SetExtraData(s.Cfg.VMName, "VBoxInternal/Devices/acpi/0/Config/AcpiOemId", "DELL  ")
	_ = s.VBox.SetExtraData(s.Cfg.VMName, "VBoxInternal/Devices/acpi/0/Config/AcpiCreatorId", "DELL")
	_ = s.VBox.SetExtraData(s.Cfg.VMName, "VBoxInternal/Devices/acpi/0/Config/AcpiCreatorRev", "0x00000001")

	msg := "Stealth applied (VBoxSVGA unchanged): " + strings.Join(notes, "; ")
	return msg, nil
}

func firmwareType(vb *vbox.Client, vmName string) (string, error) {
	out, err := vb.RunWithTimeout(time.Minute, "showvminfo", vmName, "--machinereadable")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "firmware=") {
			v := strings.TrimPrefix(line, "firmware=")
			return strings.ToLower(strings.Trim(v, `"`)), nil
		}
	}
	return "bios", nil
}

func clearPcbiosConfigExtra(vb *vbox.Client, vmName string) error {
	out, err := vb.RunWithTimeout(time.Minute, "getextradata", vmName, "enumerate")
	if err != nil {
		return err
	}
	const prefix = "VBoxInternal/Devices/pcbios/0/Config/"
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		// Key: PATH, Value: ...
		if !strings.HasPrefix(line, "Key: ") {
			continue
		}
		rest := strings.TrimPrefix(line, "Key: ")
		key, _, _ := strings.Cut(rest, ",")
		key = strings.TrimSpace(key)
		if strings.HasPrefix(key, prefix) {
			_, _ = vb.RunWithTimeout(time.Minute, "setextradata", vmName, key)
		}
	}
	return nil
}

func resolveStealthMAC(vb *vbox.Client, vmName string, st config.StealthConfig) (mac string, generated bool, err error) {
	raw := strings.TrimSpace(st.MacAddress)
	if raw == "" || strings.EqualFold(raw, "auto") {
		// Prefer an already-spoofed NIC so cold starts do not rotate the address.
		if cur, curErr := currentMAC(vb, vmName); curErr == nil && len(cur) == 12 && !strings.HasPrefix(cur, "080027") {
			return cur, false, nil
		}
		oui := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(st.MacOUI), ":", ""), "-", "")
		if oui == "" {
			oui = "F8B156" // Dell Inc.
		}
		oui = strings.ToUpper(oui)
		if len(oui) != 6 {
			return "", false, fmt.Errorf("macOui must be 6 hex digits, got %q", st.MacOUI)
		}
		var b [3]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", false, err
		}
		return oui + strings.ToUpper(hex.EncodeToString(b[:])), true, nil
	}
	mac = strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(raw, ":", ""), "-", ""))
	if len(mac) != 12 {
		return "", false, fmt.Errorf("macAddress must be 12 hex digits, got %q", raw)
	}
	for _, c := range mac {
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return "", false, fmt.Errorf("macAddress has non-hex: %q", raw)
		}
	}
	return mac, false, nil
}

func currentMAC(vb *vbox.Client, vmName string) (string, error) {
	out, err := vb.RunWithTimeout(time.Minute, "showvminfo", vmName, "--machinereadable")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "macaddress1=") {
			v := strings.TrimPrefix(line, "macaddress1=")
			v = strings.Trim(v, `"`)
			return strings.ToUpper(v), nil
		}
	}
	return "", fmt.Errorf("macaddress1 not found")
}

func persistStealthMAC(configPath, mac12 string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return err
	}
	isoRaw, ok := root["isolation"]
	var isolation map[string]any
	if ok {
		_ = json.Unmarshal(isoRaw, &isolation)
	}
	if isolation == nil {
		isolation = map[string]any{}
	}
	stealth, _ := isolation["stealth"].(map[string]any)
	if stealth == nil {
		stealth = map[string]any{}
	}
	stealth["enabled"] = true
	stealth["macAddress"] = mac12
	isolation["stealth"] = stealth
	isoBytes, err := json.Marshal(isolation)
	if err != nil {
		return err
	}
	root["isolation"] = isoBytes
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, append(out, '\n'), 0o644)
}

func formatMAC(mac12 string) string {
	if len(mac12) != 12 {
		return mac12
	}
	parts := make([]string, 0, 6)
	for i := 0; i < 12; i += 2 {
		parts = append(parts, mac12[i:i+2])
	}
	return strings.Join(parts, ":")
}

func defaultDMI(override map[string]string) map[string]string {
	out := map[string]string{
		"DmiSystemVendor":    "Dell Inc.",
		"DmiSystemProduct":   "OptiPlex 7090",
		"DmiSystemVersion":   "1.0.0",
		"DmiSystemSerial":    "JQ-LAB-7K90A1",
		"DmiSystemFamily":    "OptiPlex",
		"DmiSystemSKU":       "0A54",
		"DmiBoardVendor":     "Dell Inc.",
		"DmiBoardProduct":    "0A54",
		"DmiBoardVersion":    "A00",
		"DmiBoardSerial":     "/BN0A54-LAB001/",
		"DmiBoardAssetTag":   " ",
		"DmiChassisVendor":   "Dell Inc.",
		"DmiChassisType":     "3",
		"DmiChassisVersion":  "N/A",
		"DmiChassisSerial":   "CN-LAB-7090-001",
		"DmiChassisAssetTag": " ",
		"DmiBIOSVendor":      "Dell Inc.",
		"DmiBIOSVersion":     "1.18.0",
		"DmiBIOSReleaseDate": "12/15/2023",
	}
	for k, v := range override {
		if strings.TrimSpace(v) != "" {
			out[k] = v
		}
	}
	return out
}
