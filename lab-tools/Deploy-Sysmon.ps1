<#
.SYNOPSIS  Despliega Sysmon en una VM del lab por PowerShell Direct (copia binario + config e instala).
.DESCRIPTION
    Copia Sysmon64.exe y la config curada a la VM (C:\Tools\Sysmon) y ejecuta la instalacion.
    La VM esta aislada (sin internet), por eso se copia desde el host via PSSession sobre VMBus.
.PARAMETER VMName    VM destino (def. WIN11).
.PARAMETER User      Usuario admin del invitado (local: 'WIN11\labadmin').
.PARAMETER Pass      Contrasena (lab).
.PARAMETER SysmonExe Ruta del Sysmon64.exe en el host.
.PARAMETER ConfigXml Ruta de la config de Sysmon en el host.
.NOTES  Lab SOC Blue Team. Ejecutar en el HOST como Administrador.
#>
param(
    [string]$VMName    = "WIN11",
    [string]$User      = "WIN11\labadmin",
    [string]$Pass      = "Lab.Admin.2026!",
    [string]$SysmonExe = "C:\Users\joseq\Tools\Sysmon\Sysmon64.exe",
    [string]$ConfigXml = "$PSScriptRoot\configs\sysmon-config.xml"
)
$ErrorActionPreference = "Stop"
$cred = New-Object System.Management.Automation.PSCredential($User, (ConvertTo-SecureString $Pass -AsPlainText -Force))
$s = New-PSSession -VMName $VMName -Credential $cred
try {
    Invoke-Command -Session $s -ScriptBlock { New-Item -ItemType Directory -Force 'C:\Tools\Sysmon' | Out-Null }
    Copy-Item -ToSession $s -Path $SysmonExe -Destination 'C:\Tools\Sysmon\Sysmon64.exe' -Force
    Copy-Item -ToSession $s -Path $ConfigXml -Destination 'C:\Tools\Sysmon\sysmon-config.xml' -Force
    Invoke-Command -Session $s -ScriptBlock {
        & 'C:\Tools\Sysmon\Sysmon64.exe' -accepteula -i 'C:\Tools\Sysmon\sysmon-config.xml' 2>&1 | Out-String
        "Servicio Sysmon64: " + (Get-Service Sysmon64).Status
        $log = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
        if ($log) { "Log Operational: RecordCount=$($log.RecordCount)" }
    }
    # Para actualizar la config mas adelante: Sysmon64.exe -c C:\Tools\Sysmon\sysmon-config.xml
} finally { Remove-PSSession $s }
