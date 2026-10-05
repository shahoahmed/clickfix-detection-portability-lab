<#
  Safe ClickFix simulation for detection testing. Lab use only.
  Reproduces the telemetry of a ClickFix paste WITHOUT any network activity or payload:
    1. Writes a RunMRU entry exactly like the Win+R dialog does (Sysmon EID 13)
    2. Launches PowerShell from explorer.exe context with -w hidden and a fake CAPTCHA lure
       that only writes a harmless text file to %TEMP% (Sysmon EID 1)
  Most faithful method: paste the $Command below into Win+R manually.
#>
$Id      = Get-Random -Minimum 1000 -Maximum 9999
$Command = "powershell -w hidden -c `"'ClickFix lab simulation - harmless' | Out-File `$env:TEMP\clickfix-sim.txt`" # I am not a robot - reCAPTCHA Verification ID: $Id"
Write-Host "Paste this into Win+R (Run dialog) and press Enter:" -ForegroundColor Cyan
Write-Host $Command
Set-Clipboard -Value $Command
Write-Host "(Copied to clipboard.)"
