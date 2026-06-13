<#
.SYNOPSIS  Recrea la VM WIN11 (Gen2, vTPM, Secure Boot) con VHDX nuevo vacio, borrando restos previos.
.NOTES     Lab SOC Blue Team. Ejecutar como Administrador (Hyper-V).
#>
$ErrorActionPreference = 'Stop'
$name = 'WIN11'
$dir  = "C:\Lab\VMs\$name"
$iso  = 'C:\Lab\ISOs\Win11_25H2_x64.iso'
$sw   = 'LAB-Net'

if (Get-VM -Name $name -ErrorAction SilentlyContinue) {
    Write-Output "Quitando VM previa $name..."
    Stop-VM -Name $name -TurnOff -Force -ErrorAction SilentlyContinue
    Remove-VM -Name $name -Force
}
if (Test-Path $dir) {
    Write-Output "Borrando restos en $dir (incluye VHDX viejo de Home)..."
    Remove-Item $dir -Recurse -Force
}
New-Item -ItemType Directory -Force $dir | Out-Null

Write-Output "Creando VM $name (Gen2, 2 vCPU, 1-4 GB dyn, VHDX dinamico 64 GB)..."
New-VM -Name $name -MemoryStartupBytes 4GB -Generation 2 -Path 'C:\Lab\VMs' `
       -NewVHDPath "$dir\$name.vhdx" -NewVHDSizeBytes 64GB -SwitchName $sw | Out-Null
Set-VM -Name $name -DynamicMemory -MemoryMinimumBytes 1GB -MemoryMaximumBytes 4GB -ProcessorCount 2 `
       -AutomaticCheckpointsEnabled $false
Add-VMDvdDrive -VMName $name -Path $iso
Set-VMKeyProtector -VMName $name -NewLocalKeyProtector
Enable-VMTPM -VMName $name
$installDvd = Get-VMDvdDrive -VMName $name | Where-Object { $_.Path -eq $iso } | Select-Object -First 1
Set-VMFirmware -VMName $name -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows' -FirstBootDevice $installDvd
Write-Output "[+] WIN11 recreada (vTPM + Secure Boot, DVD=Win11 ISO)."

Get-PSDrive C | Select-Object @{N='FreeGB_tras_limpiar';E={[math]::Round($_.Free/1GB,1)}} | Format-Table -AutoSize
