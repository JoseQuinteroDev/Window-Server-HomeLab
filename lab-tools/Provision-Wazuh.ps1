<#
.SYNOPSIS  Crea la VM WAZUH (Gen2, Ubuntu) en LAB-Net + NIC de internet temporal para instalar.
.DESCRIPTION
    NIC1 = LAB-Net  (MAC ...0a:0a:20) -> IP final 10.10.10.20 (estatica, aislada; la fija cloud-init).
    NIC2 = Default Switch (MAC ...0a:0a:99) -> DHCP/NAT, internet SOLO durante la instalacion.
    Tras instalar Ubuntu + Wazuh AIO, quitar NIC2:
        Remove-VMNetworkAdapter -VMName WAZUH -SwitchName 'Default Switch'   # re-aisla el lab
    Linux en Gen2 -> Secure Boot con plantilla 'MicrosoftUEFICertificateAuthority' (firma el shim de Ubuntu).
.NOTES  Lab SOC Blue Team. Ejecutar como Administrador (Hyper-V).
#>
param(
    [string]$Name       = 'WAZUH',
    [string]$LabSwitch  = 'LAB-Net',
    [string]$NetSwitch  = 'Default Switch',
    [string]$InstallIso = 'C:\Lab\ISOs\ubuntu-24.04.4-live-server-amd64.iso',
    [string]$SeedIso    = 'C:\Lab\ISOs\wazuh-seed.iso',
    [string]$LabMac     = '00155D0A0A20',
    [string]$NetMac     = '00155D0A0A99'
)
$ErrorActionPreference = 'Stop'
$dir = "C:\Lab\VMs\$Name"

if (Get-VM -Name $Name -ErrorAction SilentlyContinue) {
    Write-Output "Quitando VM previa $Name..."
    Stop-VM -Name $Name -TurnOff -Force -ErrorAction SilentlyContinue
    Remove-VM -Name $Name -Force
}
if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
New-Item -ItemType Directory -Force $dir | Out-Null

Write-Output "Creando VM $Name (Gen2, 2 vCPU, 2-4 GB dyn, VHDX dinamico 32 GB)..."
New-VM -Name $Name -MemoryStartupBytes 4GB -Generation 2 -Path 'C:\Lab\VMs' `
       -NewVHDPath "$dir\$Name.vhdx" -NewVHDSizeBytes 32GB -SwitchName $LabSwitch | Out-Null
Set-VM -Name $Name -DynamicMemory -MemoryMinimumBytes 2GB -MemoryMaximumBytes 4GB -ProcessorCount 2 `
       -AutomaticCheckpointsEnabled $false

# MAC fija en la NIC de LAB-Net (la referencia cloud-init para la IP estatica)
Get-VMNetworkAdapter -VMName $Name | Set-VMNetworkAdapter -StaticMacAddress $LabMac
# Segunda NIC: internet NAT temporal solo para la instalacion
Add-VMNetworkAdapter -VMName $Name -SwitchName $NetSwitch -StaticMacAddress $NetMac

Add-VMDvdDrive -VMName $Name -Path $InstallIso
Add-VMDvdDrive -VMName $Name -Path $SeedIso
$installDvd = Get-VMDvdDrive -VMName $Name | Where-Object { $_.Path -eq $InstallIso } | Select-Object -First 1
Set-VMFirmware -VMName $Name -EnableSecureBoot On `
    -SecureBootTemplate 'MicrosoftUEFICertificateAuthority' -FirstBootDevice $installDvd

Write-Output "[+] $Name creada: NIC1=$LabSwitch (10.10.10.20) + NIC2=$NetSwitch (DHCP temporal), install+seed DVD."
