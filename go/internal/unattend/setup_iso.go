package unattend

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/disk"
	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"
)

// BuildBootableSetupISO copies a Windows install ISO into staging, drops answer-file
// media on top, and writes a bootable EFI ISO (Joliet + efisys_noprompt when present).
// This is the reliable way for Win11 EFI: Setup only reliably reads autounattend.xml
// from the same optical volume it boots from.
func BuildBootableSetupISO(windowsISO, mediaDir, stagingDir, destISO string) error {
	if strings.TrimSpace(windowsISO) == "" {
		return fmt.Errorf("windows ISO path is empty")
	}
	if _, err := os.Stat(windowsISO); err != nil {
		return fmt.Errorf("windows ISO: %w", err)
	}
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return err
	}

	marker := filepath.Join(stagingDir, ".quarantine-source-iso")
	srcInfo, err := os.Stat(windowsISO)
	if err != nil {
		return err
	}
	want := fmt.Sprintf("%s|%d|%d", filepath.Clean(windowsISO), srcInfo.Size(), srcInfo.ModTime().UTC().Unix())
	needSync := true
	if raw, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(raw)) == want {
		if _, err := os.Stat(filepath.Join(stagingDir, "sources")); err == nil {
			needSync = false
		}
	}
	if needSync {
		if err := syncWindowsISOToStaging(windowsISO, stagingDir); err != nil {
			return err
		}
		if err := os.WriteFile(marker, []byte(want+"\n"), 0o644); err != nil {
			return err
		}
	}

	// Overlay answer file + FirstLogon helpers at ISO root (and Quarantine\).
	if err := overlayMedia(mediaDir, stagingDir); err != nil {
		return err
	}

	bootFile := findWindowsEFIBootImage(stagingDir)
	if bootFile == "" {
		return fmt.Errorf("EFI boot file not found under %s (efi/microsoft/boot/efisys*.bin)", stagingDir)
	}

	// Win11 install.wim is typically >4GiB. ISO9660 (go-diskfs) silently truncates;
	// Setup then dies with BCD 0xc000000f. Always remaster with oscdimg + UDF.
	osc := findOscdimg()
	if osc == "" {
		return fmt.Errorf("oscdimg.exe not found (required to build bootable Win11 media with install.wim >4GiB).\n"+
			"Install: winget install --id Microsoft.OSCDIMG -e\n"+
			"Or set OSCDIMG to the full path of oscdimg.exe")
	}
	if err := writeBootableWindowsISOOscdimg(osc, stagingDir, destISO, bootFile); err != nil {
		return fmt.Errorf("oscdimg: %w", err)
	}
	_ = os.Chtimes(destISO, time.Now(), time.Now())
	return nil
}

func findWindowsEFIBootImage(stagingDir string) string {
	for _, cand := range []string{
		"efi/microsoft/boot/efisys_noprompt.bin",
		"efi/microsoft/boot/efisys.bin",
	} {
		p := filepath.Join(stagingDir, filepath.FromSlash(cand))
		if _, err := os.Stat(p); err == nil {
			return cand
		}
	}
	return ""
}

func syncWindowsISOToStaging(windowsISO, stagingDir string) error {
	entries, _ := os.ReadDir(stagingDir)
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(stagingDir, e.Name()))
	}
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return err
	}

	// Modern Win11 ISOs are UDF/Joliet hybrids. go-diskfs only sees the stub
	// ISO9660 tree (often just README.TXT), so on Windows mount via the OS.
	if runtime.GOOS == "windows" {
		if err := syncWindowsISOViaMount(windowsISO, stagingDir); err != nil {
			return fmt.Errorf("mount/copy windows ISO: %w", err)
		}
		return nil
	}

	if err := syncWindowsISOViaDiskfs(windowsISO, stagingDir); err != nil {
		return fmt.Errorf("extract windows ISO: %w (on Windows hosts, Mount-DiskImage is used instead)", err)
	}
	return nil
}

func syncWindowsISOViaMount(windowsISO, stagingDir string) error {
	// Robocopy exit 0-7 = success with varying copy/extra semantics.
	ps := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$iso = %s
$dest = %s
if (-not (Test-Path -LiteralPath $iso)) { throw "ISO not found: $iso" }
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Get-ChildItem -LiteralPath $dest -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
$img = $null
try {
  $img = Mount-DiskImage -ImagePath $iso -PassThru
  Start-Sleep -Milliseconds 800
  $vol = $img | Get-Volume
  if (-not $vol -or -not $vol.DriveLetter) {
    throw 'Mounted ISO has no drive letter'
  }
  $src = "$($vol.DriveLetter):\"
  Write-Host "Copying Windows setup media from $src -> $dest"
  & robocopy $src $dest /E /COPY:DAT /DCOPY:DAT /R:2 /W:2 /MT:8 /NFL /NDL /NJH /NJS /NC /NS /NP | Out-Null
  $code = $LASTEXITCODE
  if ($code -ge 8) { throw "robocopy failed with exit $code" }
  if (-not (Test-Path -LiteralPath (Join-Path $dest 'sources'))) {
    throw "staging missing sources\ after robocopy (exit $code)"
  }
} finally {
  if ($img) { Dismount-DiskImage -ImagePath $iso | Out-Null }
}
`, psQuote(windowsISO), psQuote(stagingDir))

	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func syncWindowsISOViaDiskfs(windowsISO, stagingDir string) error {
	d, err := diskfs.Open(windowsISO, diskfs.WithOpenMode(diskfs.ReadOnly), diskfs.WithSectorSize(2048))
	if err != nil {
		return fmt.Errorf("open windows ISO: %w", err)
	}
	defer func() { _ = d.Close() }()

	fs, err := d.GetFilesystem(0)
	if err != nil {
		return fmt.Errorf("windows ISO filesystem: %w", err)
	}

	// go-diskfs ReadDir("/") often returns EINVAL; "." works for shallow trees.
	if err := copyFSTree(fs, ".", stagingDir); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(stagingDir, "sources")); err != nil {
		return fmt.Errorf("diskfs extract incomplete (no sources/); Win11 media needs OS mount/UDF support: %w", err)
	}
	return nil
}

func copyFSTree(fs filesystem.FileSystem, fsPath, destRoot string) error {
	entries, err := fs.ReadDir(fsPath)
	if err != nil {
		return fmt.Errorf("readdir %q: %w", fsPath, err)
	}
	for _, ent := range entries {
		name := ent.Name()
		if name == "." || name == ".." {
			continue
		}
		childFS := fsPath
		switch {
		case childFS == "." || childFS == "":
			childFS = name
		case childFS == "/":
			childFS = "/" + name
		case strings.HasSuffix(childFS, "/"):
			childFS = childFS + name
		default:
			childFS = childFS + "/" + name
		}
		rel := strings.TrimPrefix(childFS, "/")
		if strings.HasPrefix(rel, "./") {
			rel = strings.TrimPrefix(rel, "./")
		}
		dest := filepath.Join(destRoot, filepath.FromSlash(rel))
		if ent.IsDir() {
			if err := os.MkdirAll(dest, 0o755); err != nil {
				return err
			}
			if err := copyFSTree(fs, childFS, destRoot); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		in, err := fs.OpenFile(childFS, os.O_RDONLY)
		if err != nil {
			// Try with leading slash for Absolute OpenFile implementations.
			in, err = fs.OpenFile("/"+strings.TrimPrefix(childFS, "/"), os.O_RDONLY)
			if err != nil {
				return fmt.Errorf("open %s: %w", childFS, err)
			}
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			_ = in.Close()
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeErr1 := in.Close()
		closeErr2 := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr1 != nil {
			return closeErr1
		}
		if closeErr2 != nil {
			return closeErr2
		}
	}
	return nil
}

func overlayMedia(mediaDir, stagingDir string) error {
	return filepath.Walk(mediaDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(mediaDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		dest := filepath.Join(stagingDir, rel)
		if info.IsDir() {
			return os.MkdirAll(dest, 0o755)
		}
		return copyFile(path, dest)
	})
}

func findOscdimg() string {
	if p := strings.TrimSpace(os.Getenv("OSCDIMG")); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("oscdimg"); err == nil {
		return p
	}
	if p, err := exec.LookPath("oscdimg.exe"); err == nil {
		return p
	}
	if runtime.GOOS != "windows" {
		return ""
	}
	// winget install Microsoft.OSCDIMG drops it under LocalAppData\Microsoft\WinGet\Packages.
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, "AppData", "Local", "Microsoft", "WinGet", "Links", "oscdimg.exe"),
		filepath.Join(home, "AppData", "Local", "Microsoft", "WindowsApps", "oscdimg.exe"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	var found string
	searchRoots := []string{
		filepath.Join(home, "AppData", "Local", "Microsoft", "WinGet", "Packages"),
		os.Getenv("ProgramFiles(x86)"),
		os.Getenv("ProgramFiles"),
	}
	for _, root := range searchRoots {
		if root == "" {
			continue
		}
		base := root
		if !strings.Contains(strings.ToLower(root), "winget") {
			base = filepath.Join(root, "Windows Kits")
		}
		_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || found != "" {
				return nil
			}
			if !info.IsDir() && strings.EqualFold(info.Name(), "oscdimg.exe") {
				found = path
				return filepath.SkipAll
			}
			return nil
		})
		if found != "" {
			return found
		}
	}
	return ""
}

func writeBootableWindowsISOOscdimg(oscdimg, stagingDir, destISO, bootFile string) error {
	if err := os.MkdirAll(filepath.Dir(destISO), 0o700); err != nil {
		return err
	}
	_ = os.Remove(destISO)

	etfs := filepath.Join(stagingDir, "boot", "etfsboot.com")
	efiBoot := filepath.Join(stagingDir, filepath.FromSlash(bootFile))
	if _, err := os.Stat(efiBoot); err != nil {
		return fmt.Errorf("EFI boot image missing: %w", err)
	}

	// Dual BIOS+UEFI catalog matching Microsoft Win11 media layout.
	bootdata := fmt.Sprintf("2#p0,e,b%s#pEF,e,b%s", etfs, efiBoot)
	if _, err := os.Stat(etfs); err != nil {
		bootdata = fmt.Sprintf("1#pEF,e,b%s", efiBoot)
	}

	args := []string{
		"-m", "-o", "-u2", "-udfver102",
		"-bootdata:" + bootdata,
		"-lWIN11SETUP",
		stagingDir,
		destISO,
	}
	cmd := exec.Command(oscdimg, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %w", args, err)
	}
	info, err := os.Stat(destISO)
	if err != nil {
		return err
	}
	// Sanity: install.wim must not be truncated vs staging.
	stageWim := filepath.Join(stagingDir, "sources", "install.wim")
	if st, err := os.Stat(stageWim); err == nil {
		// Remastered ISO should be larger than the WIM alone.
		if info.Size() < st.Size() {
			return fmt.Errorf("setup ISO too small (%d) vs install.wim (%d) — remaster likely truncated", info.Size(), st.Size())
		}
	}
	return nil
}

func writeBootableWindowsISO(stagingDir, destISO, bootFile string) error {
	var total int64
	_ = filepath.Walk(stagingDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	// ISO size ≈ payload + 128MiB headroom for structures / alignment.
	size := total + 128*1024*1024
	const block = int64(2048)
	size = ((size + block - 1) / block) * block

	if err := os.MkdirAll(filepath.Dir(destISO), 0o700); err != nil {
		return err
	}
	_ = os.Remove(destISO)

	d, err := diskfs.Create(destISO, size, diskfs.SectorSize(2048))
	if err != nil {
		return fmt.Errorf("create setup ISO: %w", err)
	}
	defer func() { _ = d.Close() }()

	fs, err := d.CreateFilesystem(disk.FilesystemSpec{
		Partition:   0,
		FSType:      filesystem.TypeISO9660,
		VolumeLabel: "WIN11SETUP",
	})
	if err != nil {
		return fmt.Errorf("create ISO9660: %w", err)
	}

	err = filepath.Walk(stagingDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(stagingDir, path)
		if err != nil {
			return err
		}
		if rel == "." || info.Name() == ".quarantine-source-iso" {
			return nil
		}
		imgPath := "/" + filepath.ToSlash(rel)
		if info.IsDir() {
			return fs.Mkdir(imgPath)
		}
		dir := filepath.ToSlash(filepath.Dir(rel))
		if dir != "." && dir != "" {
			_ = mkdirAllFS(fs, dir)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		out, err := fs.OpenFile(imgPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC)
		if err != nil {
			_ = in.Close()
			return fmt.Errorf("iso create %s: %w", imgPath, err)
		}
		_, copyErr := io.Copy(out, in)
		closeErr1 := in.Close()
		closeErr2 := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr1 != nil {
			return closeErr1
		}
		return closeErr2
	})
	if err != nil {
		_ = fs.Close()
		return err
	}

	isoFS, ok := fs.(*iso9660.FileSystem)
	if !ok {
		_ = fs.Close()
		return fmt.Errorf("unexpected fs type %T", fs)
	}

	// Joliet only: RockRidge on a full Win11 tree is huge and unnecessary for Setup.
	opts := iso9660.FinalizeOptions{
		VolumeIdentifier: "WIN11SETUP",
		Joliet:           true,
		RockRidge:        false,
		DeepDirectories:  true,
		ElTorito: &iso9660.ElTorito{
			BootCatalog: "boot.catalog",
			Entries: []*iso9660.ElToritoEntry{{
				Platform:  iso9660.EFI,
				Emulation: iso9660.NoEmulation,
				BootFile:  bootFile,
			}},
		},
	}
	if err := isoFS.Finalize(opts); err != nil {
		return fmt.Errorf("finalize setup ISO: %w", err)
	}
	_ = os.Chtimes(destISO, time.Now(), time.Now())
	return nil
}
