#Requires -Version 5.1
$log = 'C:\Users\Public\Quarantine\schtasks-test.log'
Remove-Item $log -Force -ErrorAction SilentlyContinue
function Log([string]$m) { Add-Content -LiteralPath $log -Value $m }

$credPath = 'C:\Users\Public\Quarantine\.elev-cred.json'
if (-not (Test-Path $credPath)) { Log 'NO_CRED'; exit 1 }
$c = Get-Content $credPath -Raw | ConvertFrom-Json
$user = [string]$c.user
$pass = [string]$c.password
Log "USER=$user"

$task = 'QuarantineSchtasksSmoke'
$tr = 'cmd.exe /c whoami > C:\Users\Public\Quarantine\whoami-elev.txt'
$create = schtasks.exe /Create /TN $task /TR $tr /SC ONCE /ST 00:00 /SD 01/01/2020 /RU $user /RP $pass /RL HIGHEST /F 2>&1
Log "CREATE exit=$LASTEXITCODE"
Log ($create | Out-String)
if ($LASTEXITCODE -ne 0) { exit 2 }
$run = schtasks.exe /Run /TN $task 2>&1
Log "RUN exit=$LASTEXITCODE"
Log ($run | Out-String)
Start-Sleep -Seconds 3
schtasks.exe /Delete /TN $task /F 2>&1 | Out-Null
if (Test-Path 'C:\Users\Public\Quarantine\whoami-elev.txt') {
    Log ('WHOAMI=' + (Get-Content 'C:\Users\Public\Quarantine\whoami-elev.txt' -Raw))
} else {
    Log 'NO_WHOAMI_FILE'
}
