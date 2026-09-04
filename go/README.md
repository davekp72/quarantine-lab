# Quarantine Lab (Go)

Go + Wails rewrite of the quarantine VirtualBox lab tooling.

## Build

```powershell
cd go
go build -o quarantine.exe ./cmd/quarantine
```

For the Wails desktop shell (requires [Wails CLI](https://wails.io)):

```powershell
cd go/cmd/quarantine
wails build
```

## Usage

From the repo root (uses `config/quarantine-vm.json`):

```powershell
.\quarantine-vm.ps1 status
.\quarantine-vm.ps1 snapshot -SnapshotName CleanSession -Force
.\quarantine-vm.ps1 preserve -SnapshotName hostfile
.\quarantine-vm.ps1 reset -Clean
.\quarantine-vm.ps1 manifest diff -FromSnapshot CleanSession -ToSnapshot hostfile -Refresh
.\quarantine-vm.ps1 ui
.\quarantine-vm.ps1 -Rebuild ui
```

Or run the binary directly:

```powershell
cd go
.\quarantine.exe --config ..\config\quarantine-vm.json manifest view --from CleanSession --to hostfile --refresh
```

## Architecture

| Package | Role |
|---------|------|
| `internal/config` | Load `quarantine-vm.json` |
| `internal/gateway` | Linux Quarantine-Gateway VM (create/provision/capture/CA) |
| `internal/network` | NIC modes including `gateway` |
| `internal/vbox` | VBoxManage wrapper |
| `internal/vm` | Snapshot / preserve / reset / baseline |
| `internal/guest` | Guestcontrol copy/run |
| `internal/evidence` | Sidecars, manifest publish, guest script deploy |
| `internal/diff` | Manifest diff JSON (viewer-compatible) |
| `internal/disk` | Snapshot VDI flatten cache + NTFS file read |
| `internal/registry` | Reg export parser + tree builder |
| `internal/network` | NIC modes |
| `internal/proxy` | mitmproxy subprocess |
| `internal/capture` | VirtualBox NIC trace / PCAP |
| `internal/inbox` | Transient shared folder |
| `cmd/quarantine/frontend/dist` | Wails report UI (files/registry trees, live file preview) |

## PowerShell vs Go

`quarantine-vm.ps1` prefers the Go binary for daily commands (`start`, `proxy`, `capture`, `manifest`, `ui`, …). Setup-only PowerShell paths remain for `create`, `install`, `guest-additions`, `payload`, `proxy export-ca`, and similar. Force the PowerShell path with `$env:QUARANTINE_FORCE_PS=1`.

## Tests

```powershell
cd go
go test ./...
```
