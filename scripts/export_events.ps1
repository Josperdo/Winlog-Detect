# Export recent Security log events to CSV for this demo
# Run PowerShell as Administrator

$OutDir = Join-Path (Split-Path -Parent $PSScriptRoot) "sample_data"
New-Item -ItemType Directory -Path $OutDir -ErrorAction SilentlyContinue | Out-Null
$OutFile = Join-Path $OutDir "events.csv"

# If your machine restricts script execution, you can run:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

Get-WinEvent -LogName Security -MaxEvents 5000 |
Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutFile

Write-Host "Exported to $OutFile"