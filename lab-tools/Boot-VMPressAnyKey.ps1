<#
.SYNOPSIS
    Arranca/reinicia una VM Gen2 e inyecta pulsaciones para superar el aviso
    "Press any key to boot from CD or DVD..." del instalador de Windows.
.DESCRIPTION
    En VMs Gen2, si nadie pulsa una tecla en la ventana (~5 s), cdboot.efi aborta y la VM
    cae al resumen de arranque UEFI ("The boot loader failed"). Este script teclea ENTER
    repetidamente por Msvm_Keyboard durante la ventana de arranque, sin necesidad de VMConnect.
.PARAMETER VMName
    Nombre de la VM (p.ej. DC01, WIN11).
.PARAMETER Seconds
    Duración aprox. del bombardeo de teclas (por defecto 40 s).
.EXAMPLE
    .\Boot-VMPressAnyKey.ps1 -VMName WIN11
.NOTES
    Parte del lab SOC Blue Team. Ejecutar como Administrador (Hyper-V).
#>
param(
    [Parameter(Mandatory)][string]$VMName,
    [int]$Seconds = 35,
    [double]$IntervalMs = 400   # cadencia densa: la ventana de "Press any key" dura ~5 s
)
$ErrorActionPreference = "Stop"

$vm  = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "ElementName='$VMName'"
if (-not $vm) { throw "VM no encontrada: $VMName" }
$kbd = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_Keyboard -Association Msvm_SystemDevice

$state = (Get-VM -Name $VMName).State
if ($state -eq 'Off') {
    Write-Output "Arrancando $VMName ..."
    Start-VM -Name $VMName
} else {
    Write-Output "Reiniciando $VMName ..."
    Restart-VM -Name $VMName -Force
}

# VK_RETURN = 0x0D (13). Bombardeo denso de ENTER para no perder la ventana del aviso.
$iterations = [int]($Seconds * 1000 / $IntervalMs)
Write-Output "Inyectando ENTER durante ~$Seconds s (cada $IntervalMs ms, $iterations pulsaciones)..."
for ($i = 0; $i -lt $iterations; $i++) {
    try { Invoke-CimMethod -InputObject $kbd -MethodName TypeKey -Arguments @{ keyCode = [uint32]13 } | Out-Null } catch {}
    Start-Sleep -Milliseconds $IntervalMs
}
Write-Output "Hecho. Usa Capture-VMConsole.ps1 para ver si entró al instalador."
