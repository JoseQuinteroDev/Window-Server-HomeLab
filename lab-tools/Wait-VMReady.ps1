<#
.SYNOPSIS  Espera a que una VM responda por PowerShell Direct (OS arriba + cuenta valida).
.DESCRIPTION
    Sondea Invoke-Command -VMName con la credencial dada hasta que devuelve el COMPUTERNAME
    (opcionalmente esperando uno concreto). Util para esperar instalaciones desatendidas / reinicios.
.PARAMETER VMName     Nombre de la VM.
.PARAMETER Username   Usuario invitado (local: 'labadmin'; dominio: 'CORP\Administrator').
.PARAMETER Password   Contrasena en claro (lab).
.PARAMETER ExpectName Si se indica, exige que COMPUTERNAME coincida.
.PARAMETER MaxMinutes Tiempo maximo de espera.
.NOTES Lab SOC Blue Team. Ejecutar como Administrador.
#>
param(
    [Parameter(Mandatory)][string]$VMName,
    [Parameter(Mandatory)][string]$Username,
    [Parameter(Mandatory)][string]$Password,
    [string]$ExpectName,
    [int]$MaxMinutes = 9
)
$ErrorActionPreference = 'Stop'
$sec  = ConvertTo-SecureString $Password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($Username, $sec)
$deadline = (Get-Date).AddMinutes($MaxMinutes)
$n = 0
while ((Get-Date) -lt $deadline) {
    $n++
    Start-Sleep -Seconds 10
    try {
        $name = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
        if (-not $ExpectName -or $name -eq $ExpectName) {
            Write-Output ("[sondeo {0}] LISTO - COMPUTERNAME={1}" -f $n, $name)
            exit 0
        }
        Write-Output ("[sondeo {0}] responde pero COMPUTERNAME={1} (espero {2})" -f $n, $name, $ExpectName)
    } catch {
        Write-Output ("[sondeo {0}] aun no disponible (instalando/reiniciando)..." -f $n)
    }
}
Write-Output ("=== TIMEOUT tras {0} min ===" -f $MaxMinutes)
exit 1
