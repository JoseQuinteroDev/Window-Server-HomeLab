<#
.SYNOPSIS  Configura red de WIN11 y la une al dominio corp.local, por PowerShell Direct (FASE 3.2).
.DESCRIPTION
    IP estatica 10.10.10.21, DNS al DC, Add-Computer al dominio y reinicio. Verifica la confianza.
    Requisitos: WIN11 instalada (Win11 Pro) con cuenta local conocida; DC01 operativo.
.NOTES  Lab SOC Blue Team. Ejecutar en el HOST como Administrador.
#>
param(
    [string]$VMName    = "WIN11",
    [string]$LocalUser = "labadmin",
    [string]$LocalPass = "Lab.Admin.2026!",
    [string]$Domain    = "corp.local",
    [string]$NetBIOS   = "CORP",
    [string]$DomAdmin  = "CORP\Administrator",
    [string]$DomPass   = "Lab.Admin.2026!",
    [string]$IP        = "10.10.10.21",
    [int]   $Prefix    = 24,
    [string]$DC_IP     = "10.10.10.10"
)
$ErrorActionPreference = "Stop"
$secLoc  = ConvertTo-SecureString $LocalPass -AsPlainText -Force
$credLoc = New-Object System.Management.Automation.PSCredential("$VMName\$LocalUser", $secLoc)

Write-Host ">>> Red + union al dominio..."
$r = Invoke-Command -VMName $VMName -Credential $credLoc -ScriptBlock {
    param($IP, $Prefix, $DC_IP, $Domain, $DomAdmin, $DomPass)
    $a = "Ethernet"
    Get-NetIPAddress -InterfaceAlias $a -AddressFamily IPv4 -EA SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '169.254*' } | Remove-NetIPAddress -Confirm:$false -EA SilentlyContinue
    Set-NetIPInterface -InterfaceAlias $a -Dhcp Disabled -EA SilentlyContinue
    New-NetIPAddress -InterfaceAlias $a -IPAddress $IP -PrefixLength $Prefix | Out-Null
    Set-DnsClientServerAddress -InterfaceAlias $a -ServerAddresses $DC_IP
    $ldap  = Test-NetConnection -ComputerName $DC_IP -Port 389 -WarningAction SilentlyContinue
    $dcred = New-Object System.Management.Automation.PSCredential($DomAdmin, (ConvertTo-SecureString $DomPass -AsPlainText -Force))
    $joined = $false; $err = $null
    try { Add-Computer -DomainName $Domain -Credential $dcred -Force -EA Stop; $joined = $true } catch { $err = $_.Exception.Message }
    [pscustomobject]@{ LdapReachable = $ldap.TcpTestSucceeded; Joined = $joined; Error = $err }
} -ArgumentList $IP, $Prefix, $DC_IP, $Domain, $DomAdmin, $DomPass
$r | Format-List

if ($r.Joined) {
    Restart-VM -Name $VMName -Force
    Write-Host ">>> Unido. Reiniciando. Verifica luego con:"
    Write-Host "    Invoke-Command -VMName $VMName -Credential (Get-Credential $VMName\$LocalUser) { (Get-CimInstance Win32_ComputerSystem).Domain; Test-ComputerSecureChannel }"
} else {
    Write-Host ">>> NO se unio: $($r.Error)"
}
