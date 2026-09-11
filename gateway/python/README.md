# Gateway Python pins (reproducible installs)

Provisioning installs mitmproxy and FakeNet from **locked** artifacts:

| File | Purpose |
|------|---------|
| `requirements-mitm.txt` | mitmproxy 12.2.3 + transitive deps with SHA-256 hashes |
| `requirements-fakenet.txt` | FakeNet runtime deps with SHA-256 hashes |
| `fakenet-source.pin` | FakeNet-NG GitHub commit archive URL + SHA-256 (not `master`) |
| `generate-locks.py` | Regenerates the hashed requirements from curated exact pins |

## Install paths

- `first-boot.sh` → `pip install --require-hashes -r python/requirements-mitm.txt`
- `install-fakenet.sh` → hashed deps, then download zip, `sha256sum -c`, `pip install --no-deps`

## Updating pins (deliberate)

1. Edit exact versions in `generate-locks.py` (stay inside mitmproxy's declared upper bounds).
2. Run: `python gateway/python/generate-locks.py`
3. For FakeNet: pick a reviewed tag/commit, download the commit zip, update `fakenet-source.pin` (`FAKENET_COMMIT`, `FAKENET_URL`, `FAKENET_SHA256`).
4. Re-provision a lab gateway and smoke-test FakeNet + permissive MITM before merging.
