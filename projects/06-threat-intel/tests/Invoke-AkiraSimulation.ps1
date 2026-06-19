<#
.SYNOPSIS
    Simula de forma CONTROLADA E INOFENSIVA los TTPs de Akira cubiertos por las detecciones
    derivadas del Proyecto 6, para validar las reglas Wazuh 100181/100190-100230 una vez
    desplegadas en el manager. Se ejecuta desde el HOST por PowerShell Direct contra WIN11.
.DESCRIPTION
    Triggers (todos benignos: recon de solo-lectura o marcadores 'echo' que NO ejecutan la accion):
      1. T1018/T1482  Recon de dominio  -> nltest /dclist + net group "Domain Admins" (REAL, solo lectura) -> 4688 -> 100200
      2. T1003.001    Volcado LSASS     -> marcador: comsvcs.dll MiniDump (echo, NO vuelca LSASS)          -> 4688 -> 100190
      3. T1087.002    BloodHound        -> Write-Output 'Invoke-BloodHound -CollectionMethod All'          -> 4104 -> 100210/100211
      4. T1136.001    Crear cuenta      -> marcador: net user ... /add (echo, NO crea cuenta)              -> 4688 -> 100220
      5. T1021.001    Habilitar RDP     -> marcador: netsh advfirewall add rule rdp 3389 (echo)            -> 4688 -> 100230
      6. T1490        Borrar shadows    -> marcador: Get-WmiObject Win32_Shadowcopy ForEach-Object Delete  -> 4688 -> 100181
    El tag "SOC-AKIRA-SIM" marca todos los eventos para localizarlos en el SIEM.
    NADA es destructivo: no se vuelca LSASS, no se crea cuenta, no se toca el firewall ni las shadow copies.
.NOTES
    Lab SOC Blue Team (corp.local). Ejecutar en el HOST como Administrador, con WIN11 encendida.
    REQUISITO: haber desplegado antes detections/wazuh/akira-local-rules.xml en el manager (ver
    evidence/deployment-and-validation.md). Derivado del informe CTI de Akira (CISA AA24-109A).
#>
param(
    [string]$Pass = "Lab.Admin.2026!"
)
$ErrorActionPreference = "Stop"
$sec = ConvertTo-SecureString $Pass -AsPlainText -Force
$dom = New-Object System.Management.Automation.PSCredential("CORP\Administrator", $sec)
$TAG = "SOC-AKIRA-SIM"

Write-Host ">>> [1] T1018/T1482 Recon de dominio (nltest + net group) — REAL, solo lectura"
Invoke-Command -VMName WIN11 -Credential $dom -ScriptBlock {
    & nltest.exe /dclist:corp.local       2>$null | Out-Null
    & nltest.exe /domain_trusts            2>$null | Out-Null
    & net.exe group "Domain Admins" /domain 2>$null | Out-Null
}

Write-Host ">>> [2-6] Marcadores benignos de LSASS / BloodHound / cuenta / RDP / shadow copies (en WIN11)"
Invoke-Command -VMName WIN11 -Credential $dom -ArgumentList $TAG -ScriptBlock {
    param($TAG)
    # 2) T1003.001 LSASS via comsvcs.dll MiniDump  (marcador: NO vuelca nada)
    & cmd.exe /c "echo $TAG rundll32.exe comsvcs.dll MiniDump 123 C:\temp\out.dmp full" | Out-Null
    # 3) T1087.002 BloodHound/SharpHound  (genera Script Block 4104 con la cadena)
    & powershell.exe -NoProfile -Command "Write-Output '$TAG Invoke-BloodHound -CollectionMethod All'" | Out-Null
    # 4) T1136.001 Crear cuenta  (marcador: NO crea cuenta)
    & cmd.exe /c "echo $TAG net user socsim_tmp P@ssw0rd.SIM /add" | Out-Null
    # 5) T1021.001 Habilitar RDP  (marcador: NO toca el firewall)
    & cmd.exe /c "echo $TAG netsh advfirewall firewall add rule name=rdp dir=in action=allow protocol=TCP localport=3389" | Out-Null
    # 6) T1490 Borrar shadow copies via WMI  (marcador: NO borra nada)
    & cmd.exe /c "echo $TAG Get-WmiObject Win32_Shadowcopy ForEach-Object Delete" | Out-Null
}
Write-Host ">>> Triggers lanzados. En el manager Wazuh, espera unos segundos y verifica:"
Write-Host "    grep -E '10018[01]|10019[01]|1002[0-3]0|100211' /var/ossec/logs/alerts/alerts.log"
Write-Host "    (o busca el tag $TAG). Compara con evidence/deployment-and-validation.md."
