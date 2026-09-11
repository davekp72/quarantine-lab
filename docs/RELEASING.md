# Releasing

Keep **source** on `main`. Publish versioned Windows binaries only through
GitHub Releases (checksums, SBOM, Sigstore signatures).

## Tag a release

```powershell
git tag -a v1.2.3 -m "v1.2.3"
git push origin v1.2.3
```

The `release` workflow builds `quarantine.exe` and `quarantine-agent.exe`,
writes SHA-256 checksums, generates an SBOM, and signs checksums with
[Sigstore](https://www.sigstore.dev/) (keyless, GitHub OIDC).

Verify:

```powershell
# checksums
Get-FileHash .\quarantine.exe -Algorithm SHA256

# optional: cosign (needs the release checksums + cert/sig assets)
cosign verify-blob checksums.txt --signature checksums.txt.sig --certificate checksums.txt.pem --certificate-identity-regexp 'https://github.com/.+/.github/workflows/release.yml@.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Sysmon is not a release artifact

Do not attach `Sysmon64.exe`. Users download it with `.\scripts\Get-Sysmon.ps1`.

## Remove Sysmon from Git history (before promoting a public clone)

Deleting `tools/Sysmon64.exe` from `main` does **not** remove it from older
commits. Microsoft’s Sysinternals FAQ forbids redistribution, so purge history
once, then force-push (this rewrites `main`):

```powershell
# Requires git-filter-repo: https://github.com/newren/git-filter-repo
git filter-repo --path tools/Sysmon64.exe --invert-paths --force
git push --force origin main
```

Coordinate with anyone who already cloned. After the rewrite they must
re-clone or reset to the new `origin/main`.
