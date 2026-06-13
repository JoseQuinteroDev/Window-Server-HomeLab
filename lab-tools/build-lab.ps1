# =====================================================================
#  C:\Lab\build-lab.ps1  —  Monta el lab SOC (FASE 0.2-0.3 + crear DC01 y WIN11)
#  Automatiza fielmente LAB-BUILD.md (Desktop\SOC-Blue-Team\LAB-BUILD.md).
#
#  EJECUTAR EN POWERSHELL **COMO ADMINISTRADOR**.
#  Idempotente: si el switch/VM ya existe, lo salta.
#  NO arranca las VMs (las arrancas tú, de una en una, por el disco justo).
#  KALI no se incluye (diferido: SSD externo / más disco).
# =====================================================================
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$IsoServer  = 'C:\Lab\ISOs\WinServer2025_Eval_x64.iso'   # DC01
$IsoWin11   = 'C:\Lab\ISOs\Win11_25H2_x64.iso'           # WIN11
$SwitchName = 'LAB-Net'                                  # Internal, AISLADO (10.10.10.0/24)
$HostIP     = '10.10.10.1'

foreach ($iso in @($IsoServer, $IsoWin11)) {
    if (-not (Test-Path $iso)) { throw "Falta el ISO: $iso" }
}
New-Item -ItemType Directory -Force 'C:\Lab\VMs' | Out-Null

# ---------- FASE 0.2: vSwitch interno aislado + IP del host ----------
if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
    Write-Host "[+] vSwitch '$SwitchName' (Internal, aislado) creado."
} else {
    Write-Host "[=] vSwitch '$SwitchName' ya existe."
}
# IP del host en LAB-Net (para gestionar/copiar archivos a las VMs)
$ifIndex = (Get-NetAdapter | Where-Object { $_.Name -like "*$SwitchName*" }).ifIndex
if ($ifIndex -and -not (Get-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $HostIP -ErrorAction SilentlyContinue)) {
    New-NetIPAddress -IPAddress $HostIP -PrefixLength 24 -InterfaceIndex $ifIndex | Out-Null
    Write-Host "[+] Host con IP $HostIP en $SwitchName."
} else {
    Write-Host "[=] Host ya tiene IP en $SwitchName (o adaptador no listo aún)."
}

# ---------- Helper para crear una VM Gen2 ----------
function New-LabVM {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$DiskGB,
        [Parameter(Mandatory)][string]$Iso,
        [switch]$EnableTpm
    )
    if (Get-VM -Name $Name -ErrorAction SilentlyContinue) {
        Write-Host "[=] VM '$Name' ya existe, la salto."
        return
    }
    $dir = "C:\Lab\VMs\$Name"
    New-Item -ItemType Directory -Force $dir | Out-Null
    New-VM -Name $Name -MemoryStartupBytes 4GB -Generation 2 -Path 'C:\Lab\VMs' `
           -NewVHDPath "$dir\$Name.vhdx" -NewVHDSizeBytes ($DiskGB * 1GB) -SwitchName $SwitchName | Out-Null
    # VHDX dinámico (por defecto en New-VM): solo ocupa lo real.
    Set-VM -Name $Name -DynamicMemory -MemoryMinimumBytes 1GB -MemoryMaximumBytes 4GB -ProcessorCount 2 `
           -AutomaticCheckpointsEnabled $false
    Add-VMDvdDrive -VMName $Name -Path $Iso
    $dvd = Get-VMDvdDrive -VMName $Name
    Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows' -FirstBootDevice $dvd
    if ($EnableTpm) {
        # Win11 EXIGE TPM 2.0: key protector local + vTPM (método de la guía)
        Set-VMKeyProtector -VMName $Name -NewLocalKeyProtector
        Enable-VMTPM -VMName $Name
        Write-Host "    -> vTPM habilitado."
    }
    Write-Host "[+] VM '$Name' creada (Gen2, 2 vCPU, 1-4 GB dyn, VHDX dinámico $DiskGB GB)."
}

# ---------- FASE 1.1: DC01 (Server 2025) ----------
New-LabVM -Name 'DC01'  -DiskGB 40 -Iso $IsoServer

# ---------- FASE 3.1: WIN11 (endpoint, requiere vTPM) ----------
New-LabVM -Name 'WIN11' -DiskGB 64 -Iso $IsoWin11 -EnableTpm

Write-Host ""
Write-Host "================ LAB BASE CREADO ================"
Write-Host "Arranca DE UNA EN UNA (disco/RAM justos). Empieza por DC01:"
Write-Host "   Start-VM DC01 ; vmconnect.exe localhost DC01"
Write-Host "Instala Server 2025 -> 'Standard Evaluation (Desktop Experience)'."
Write-Host "Sigue en LAB-BUILD.md FASE 1.2 -> 1.4 (promover a DC corp.local)."
Write-Host ""
Write-Host "Tras instalar DC01, recupera ~7.6 GB:  Remove-Item '$IsoServer'"
Write-Host "Tras instalar WIN11, recupera ~7.9 GB:  Remove-Item '$IsoWin11'"
