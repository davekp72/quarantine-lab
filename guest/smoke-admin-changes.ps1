#Requires -RunAsAdministrator
Add-Content -LiteralPath 'C:\Windows\System32\drivers\etc\hosts' -Value "`n127.0.0.1 smoke.lab.test"
'quarantine admin marker' | Set-Content -LiteralPath 'C:\Windows\smoke-lab-marker.txt' -Encoding UTF8
Write-Output 'ADMIN_CHANGES_OK'
