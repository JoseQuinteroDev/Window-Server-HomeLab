<#
.SYNOPSIS  Arranca una VM Gen2 al instalador de Windows de forma fiable, reintentando hasta lograrlo.
.DESCRIPTION
    El aviso "Press any key to boot from CD or DVD" dura ~5 s y el timing en frio es irregular.
    Este script fija el orden de arranque DVD->HDD (sin PXE, fallos rapidos) y en bucle reinicia +
    inyecta ENTER denso por Msvm_Keyboard; detecta exito por el salto de MemoryDemand (Setup/WinPE
    consume ~1 GB). Disco vacio => un fallo solo cae al resumen UEFI (inocuo).
.NOTES Lab SOC Blue Team. Ejecutar como Administrador.
#>
param(
    [Parameter(Mandatory)][string]$VMName,
    [int]$MaxAttempts = 8,
    [int]$InjectSeconds = 30,
    [int]$IntervalMs = 200,
    [string]$InstallIsoLike = '*Win11*'
)
$ErrorActionPreference = 'Stop'

$vmWmi = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "ElementName='$VMName'"
$kbd   = Get-CimAssociatedInstance -InputObject $vmWmi -ResultClassName Msvm_Keyboard -Association Msvm_SystemDevice

$dvd = Get-VMDvdDrive -VMName $VMName | Where-Object { $_.Path -like $InstallIsoLike } | Select-Object -First 1
$hdd = Get-VMHardDiskDrive -VMName $VMName | Select-Object -First 1
if ($dvd -and $hdd) { Set-VMFirmware -VMName $VMName -BootOrder $dvd, $hdd }

$iter = [int]($InjectSeconds * 1000 / $IntervalMs)
for ($a = 1; $a -le $MaxAttempts; $a++) {
    $state = (Get-VM -Name $VMName).State
    if ($state -eq 'Off') { Start-VM -Name $VMName | Out-Null } else { Restart-VM -Name $VMName -Force | Out-Null }
    Write-Output ("[intento {0}] arrancando + inyectando ENTER ({1} pulsaciones)..." -f $a, $iter)
    Start-Sleep -Milliseconds 1500
    for ($i = 0; $i -lt $iter; $i++) {
        try { Invoke-CimMethod -InputObject $kbd -MethodName TypeKey -Arguments @{ keyCode = [uint32]13 } | Out-Null } catch {}
        Start-Sleep -Milliseconds $IntervalMs
    }
    Start-Sleep -Seconds 8
    $md = (Get-VM -Name $VMName).MemoryDemand
    $mdGB = [math]::Round($md / 1GB, 2)
    if ($md -gt 700MB) {
        Write-Output ("[intento {0}] OK - Setup cargado (MemoryDemand={1} GB)." -f $a, $mdGB)
        exit 0
    }
    Write-Output ("[intento {0}] aun no (MemoryDemand={1} GB), reintento..." -f $a, $mdGB)
}
Write-Output ("=== Agotados {0} intentos ===" -f $MaxAttempts)
exit 1
