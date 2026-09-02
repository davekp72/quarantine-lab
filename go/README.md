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
.\quarantine-go.ps1 status
.\quarantine-go.ps1 snapshot --name CleanSession --force
.\quarantine-go.ps1 preserve --label hostfile
.\quarantine-go.ps1 reset --clean
.\quarantine-go.ps1 manifest diff --from CleanSession --to hostfile --refresh
.\quarantine-go.ps1 manifest view --from CleanSession --to hostfile --refresh
.\quarantine-go.ps1 ui
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
| `internal/vbox` | VBoxManage wrapper |
| `internal/vm` | Snapshot / preserve / reset / baseline |
| `internal/guest` | Guestcontrol copy/run |
| `internal/evidence` | Sidecars, manifest publish, guest script deploy |
| `internal/diff` | Manifest diff JSON (viewer-compatible) |
| `internal/disk` | Snapshot VDI flatten cache + NTFS file read |
| `internal/registry` | Reg export parser + tree builder |
| `internal/network` | NIC modes |
| `internal/proxy` | mitmproxy subprocess |
| `internal/capture` | tshark PCAP |
| `internal/inbox` | Transient shared folder |
| `cmd/quarantine/frontend/dist` | Wails report UI (files/registry trees, live file preview) |

## Migration from PowerShell

The legacy entry point `quarantine-vm.ps1` remains for now. The Go app reads the same config, sidecars under `manifest.logDir`, and VBox VM layout. Guest capture still uses the existing PowerShell scripts in `guest/` and `manifest/` (deployed via `manifest deploy`).

Once parity is verified in your lab, prefer `quarantine-go.ps1` / `quarantine.exe` for daily workflow.

## Tests

```powershell
cd go
go test ./...
```
