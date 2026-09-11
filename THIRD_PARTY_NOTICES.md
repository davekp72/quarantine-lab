# Third-party notices

Quarantine Lab incorporates, patches, or downloads the following components.
This file is attribution, not a grant of extra rights. Each component remains
under its own license. See also `NOTICE` and `LICENSE` (Apache-2.0).

Noriben is **not** included in this repository.

## FakeNet-NG (Mandiant / Google)

- Source: https://github.com/mandiant/flare-fakenet-ng
- License: Apache-2.0
- How it is used: the Linux gateway downloads a **pinned commit** at provision
  time (`gateway/python/fakenet-source.pin`) and installs it into a dedicated
  venv. Quarantine Lab ships local patches under `gateway/fakenet/`
  (HTTPS/CONNECT, privilege check for non-root, SSL utils).
- Do not confuse those patches with upstream FakeNet.

## mitmproxy

- Source: https://mitmproxy.org / https://github.com/mitmproxy/mitmproxy
- License: MIT
- How it is used: host venv (`requirements.txt`) and hashed gateway pins
  (`gateway/python/requirements-mitm.txt`) for TLS inspection in permissive mode.
  Addon code lives under `network/proxy/` and `gateway/mitm/`.

## Sysmon (Microsoft Sysinternals)

- Download: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- License: Microsoft Sysinternals software license
  (https://learn.microsoft.com/en-us/sysinternals/license-faq)
- How it is used: **not redistributed**. `scripts/Get-Sysmon.ps1` downloads
  Sysmon from Microsoft, verifies Authenticode, and stages `tools/Sysmon64.exe`
  locally. A lab config XML (`config/sysmon/`) is original to this project.

## Oracle VirtualBox

- https://www.virtualbox.org
- License: GPLv3 (open-source edition) / VirtualBox PUEL for the Extension Pack
- How it is used: the hypervisor for the Windows guest and Linux gateway.
  Extension Pack is optional and not required by this project’s default path.

## Wails

- https://wails.io / https://github.com/wailsapp/wails
- License: MIT
- How it is used: desktop UI shell (`go/cmd/quarantine`).

## Velocidex go-ntfs and regparser

- https://github.com/Velocidex/go-ntfs
- https://github.com/Velocidex/regparser (module `www.velocidex.com/golang/regparser`)
- License: Apache-2.0 (go-ntfs); see the regparser repository for its license
- How they are used: host-side NTFS reads from snapshot disks and registry hive parsing.

## Other Go / Python libraries

Direct and transitive Go modules are declared in `go/go.mod` and `go/go.sum`.
Python pins are in `requirements.txt` and `gateway/python/`. Generate an SBOM
from a release (`docs/RELEASING.md`) for a complete inventory.

## Ubuntu cloud images (gateway VM)

Gateway create may download an Ubuntu cloud image under Canonical’s terms.
That image is not stored in this repository.
