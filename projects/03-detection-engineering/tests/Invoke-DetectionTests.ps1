<#
.SYNOPSIS
    Simula (de forma controlada e inofensiva) las técnicas cubiertas por las detecciones del
    Proyecto 3 y captura la telemetría que generan. Se ejecuta desde el HOST por PowerShell Direct.
.DESCRIPTION
    Triggers:
      1. Kerberoasting (T1558.003)  -> solicita el TGS del SPN señuelo svc_sql            -> DC 4769
      2. PowerShell ofuscado (T1059.001) -> -EncodedCommand cuyo scriptblock usa IEX       -> 4104 + 4688
      3. Tamper Defender (T1562.001) -> Add-MpPreference por cmdline (se revierte)          -> Sysmon EID1
      4. LOLBin descarga (T1105)     -> certutil -urlcache http://...                       -> 4688
    Nada de esto es dañino: el cradle solo imprime texto, la exclusion se elimina, y la URL es local.
    AS-REP Roasting (T1558.004): el señuelo a.garcia existe; el disparo real requiere KALI/Rubeus.
.NOTES  Lab SOC Blue Team. Ejecutar en el HOST como Administrador.
#>
param(
    [string]$Pass = "Lab.Admin.2026!"
)
$ErrorActionPreference = "Stop"
$sec = ConvertTo-SecureString $Pass -AsPlainText -Force
$wl  = New-Object System.Management.Automation.PSCredential("WIN11\labadmin", $sec)
$dom = New-Object System.Management.Automation.PSCredential("CORP\Administrator", $sec)

Write-Host ">>> [1] Kerberoasting: TGS de MSSQLSvc/sql01.corp.local:1433"
Invoke-Command -VMName WIN11 -Credential $dom -ScriptBlock {
    Add-Type -AssemblyName System.IdentityModel
    $null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sql01.corp.local:1433"
}

Write-Host ">>> [2-4] PowerShell ofuscado + tamper Defender + LOLBin certutil (en WIN11)"
Invoke-Command -VMName WIN11 -Credential $wl -ScriptBlock {
    $inner = 'IEX "Write-Output ''SOC-DE-PS-MARKER''"'
    $enc   = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
    & powershell.exe -NoProfile -EncodedCommand $enc | Out-Null
    & powershell.exe -NoProfile -Command "Add-MpPreference -ExclusionPath 'C:\soc-de-test-REMOVEME' -EA SilentlyContinue; Remove-MpPreference -ExclusionPath 'C:\soc-de-test-REMOVEME' -EA SilentlyContinue" | Out-Null
    & certutil.exe -urlcache -f "http://127.0.0.1/soc-de-test" "$env:TEMP\soc-de-test.bin" 2>$null | Out-Null
    Remove-Item "$env:TEMP\soc-de-test.bin" -EA SilentlyContinue
}
Write-Host ">>> Triggers lanzados. Revisa los eventos (ver evidence/test-results.md) tras unos segundos."
