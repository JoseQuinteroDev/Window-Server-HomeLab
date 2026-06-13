<#
.SYNOPSIS
    Captura la pantalla de la consola de una VM Hyper-V (sin abrir VMConnect) a un PNG.
.DESCRIPTION
    Usa Msvm_VirtualSystemManagementService.GetVirtualSystemThumbnailImage (WMI de Hyper-V,
    namespace root\virtualization\v2). Util para "ver" en qué pantalla esta una VM headless:
    instalador, pantalla de bloqueo, error de arranque UEFI, etc.
.PARAMETER VMName
    Nombre de la VM (p.ej. DC01, WIN11).
.PARAMETER OutPath
    Ruta del PNG de salida. Por defecto: .\<VMName>_console.png
.EXAMPLE
    .\Capture-VMConsole.ps1 -VMName DC01
.NOTES
    Parte del lab SOC Blue Team. Ejecutar como Administrador (Hyper-V).
#>
param(
    [Parameter(Mandatory)][string]$VMName,
    [string]$OutPath,
    [int]$Width  = 1024,
    [int]$Height = 768
)
$ErrorActionPreference = "Stop"
if (-not $OutPath) { $OutPath = Join-Path (Get-Location) "$($VMName)_console.png" }

$vsms = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_VirtualSystemManagementService
$vm   = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "ElementName='$VMName'"
if (-not $vm) { throw "VM no encontrada: $VMName" }
$settings = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_VirtualSystemSettingData -Association Msvm_SettingsDefineState

$res = Invoke-CimMethod -InputObject $vsms -MethodName GetVirtualSystemThumbnailImage `
    -Arguments @{ TargetSystem = $settings; WidthPixels = [uint16]$Width; HeightPixels = [uint16]$Height }
if (-not $res.ImageData) { throw "Sin datos de imagen (ReturnValue=$($res.ReturnValue)). ¿VM apagada?" }

Add-Type -AssemblyName System.Drawing
$bmp  = New-Object System.Drawing.Bitmap($Width, $Height, [System.Drawing.Imaging.PixelFormat]::Format16bppRgb565)
$rect = New-Object System.Drawing.Rectangle(0, 0, $Width, $Height)
$bd   = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::WriteOnly, [System.Drawing.Imaging.PixelFormat]::Format16bppRgb565)
[System.Runtime.InteropServices.Marshal]::Copy($res.ImageData, 0, $bd.Scan0, [Math]::Min($res.ImageData.Length, $bd.Stride * $Height))
$bmp.UnlockBits($bd)
$bmp.Save($OutPath, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output "Captura guardada: $OutPath"
