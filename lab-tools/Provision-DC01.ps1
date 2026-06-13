<#
.SYNOPSIS
    Promociona DC01 (Server 2025 ya instalado) a Controlador de Dominio de corp.local y crea
    la estructura AD + señuelos de ataque, TODO por PowerShell Direct desde el host (sin red).
.DESCRIPTION
    Equivale a FASE 1.3 -> 2 de LAB-BUILD.md. Maneja los reinicios con sondeos de reconexion.
    Requisitos: DC01 instalada y con cuenta Administrator local conocida ($AdminPass).
.NOTES  Lab SOC Blue Team. Ejecutar en el HOST como Administrador (Hyper-V).
#>
param(
    [string]$VMName     = "DC01",
    [string]$AdminPass  = "Lab.Admin.2026!",
    [string]$Domain     = "corp.local",
    [string]$NetBIOS    = "CORP",
    [string]$DsrmPass   = "Lab.SafeMode.2026!",
    [string]$IP         = "10.10.10.10",
    [int]   $Prefix     = 24,
    [string]$UserPass   = "P@ssw0rd.2026"
)
$ErrorActionPreference = "Stop"
$secAdmin = ConvertTo-SecureString $AdminPass -AsPlainText -Force
$credLoc  = New-Object System.Management.Automation.PSCredential("Administrator", $secAdmin)
$credDom  = New-Object System.Management.Automation.PSCredential("$NetBIOS\Administrator", $secAdmin)

function Wait-PSDirect($creds, [int]$Min = 10, [scriptblock]$Test) {
    $deadline = (Get-Date).AddMinutes($Min)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 6
        foreach ($c in $creds) {
            try {
                $ok = Invoke-Command -VMName $VMName -Credential $c -ScriptBlock $Test -ErrorAction Stop
                if ($ok) { return $c }
            } catch {}
        }
    }
    throw "Timeout esperando a $VMName"
}

# ---- FASE 1.3: IP estatica + DNS propio + rename + reinicio ----
Write-Host ">>> FASE 1.3 IP/DNS/rename..."
Invoke-Command -VMName $VMName -Credential $credLoc -ScriptBlock {
    param($IP, $Prefix)
    $a = "Ethernet"
    Get-NetIPAddress -InterfaceAlias $a -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '169.254*' } | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    Set-NetIPInterface -InterfaceAlias $a -Dhcp Disabled -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceAlias $a -IPAddress $IP -PrefixLength $Prefix | Out-Null
    Set-DnsClientServerAddress -InterfaceAlias $a -ServerAddresses 127.0.0.1
} -ArgumentList $IP, $Prefix
Invoke-Command -VMName $VMName -Credential $credLoc -ScriptBlock { Rename-Computer -NewName $using:VMName -Force -Restart }
Wait-PSDirect @($credLoc) -Min 6 -Test { $env:COMPUTERNAME } | Out-Null

# ---- FASE 1.4: AD DS + bosque (reinicia solo) ----
Write-Host ">>> FASE 1.4 AD DS + Install-ADDSForest $Domain..."
Invoke-Command -VMName $VMName -Credential $credLoc -ScriptBlock {
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
}
try {
    Invoke-Command -VMName $VMName -Credential $credLoc -ScriptBlock {
        param($Domain, $NetBIOS, $DsrmPass)
        Import-Module ADDSDeployment
        Install-ADDSForest -DomainName $Domain -DomainNetbiosName $NetBIOS -InstallDns -Force `
            -SafeModeAdministratorPassword (ConvertTo-SecureString $DsrmPass -AsPlainText -Force) `
            -WarningAction SilentlyContinue | Out-Null
    } -ArgumentList $Domain, $NetBIOS, $DsrmPass
} catch { Write-Host "  (sesion cortada por el reinicio de promocion, esperado)" }
Write-Host ">>> Esperando a que el dominio este operativo..."
$cred = Wait-PSDirect @($credDom, $credLoc) -Min 12 -Test { try { (Get-ADDomain).DNSRoot -eq $using:Domain } catch { $false } }

# ---- FASE 2: OUs, usuarios, grupos, señuelos ----
Write-Host ">>> FASE 2 estructura AD + señuelos..."
Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
    param($UserPass)
    $ErrorActionPreference = "Stop"; Import-Module ActiveDirectory
    $base = (Get-ADDomain).DistinguishedName
    foreach ($ou in "Employees","Servers","Workstations","ServiceAccounts","Groups","AdminAccounts") {
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -SearchBase $base -EA SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $ou -Path $base -ProtectedFromAccidentalDeletion $false }
    }
    $pw = ConvertTo-SecureString $UserPass -AsPlainText -Force
    foreach ($u in @(
        @{N="Juan Perez";S="j.perez"}, @{N="Maria Lopez";S="m.lopez"},
        @{N="Ana Garcia";S="a.garcia"}, @{N="Helpdesk Op";S="helpdesk"})) {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.S)'" -EA SilentlyContinue)) {
            New-ADUser -Name $u.N -SamAccountName $u.S -UserPrincipalName "$($u.S)@$((Get-ADDomain).DNSRoot)" `
                -Path "OU=Employees,$base" -AccountPassword $pw -Enabled $true -ChangePasswordAtLogon $false }
    }
    foreach ($g in "IT-Admins","Finance") {
        if (-not (Get-ADGroup -Filter "Name -eq '$g'" -EA SilentlyContinue)) {
            New-ADGroup -Name $g -GroupScope Global -Path "OU=Groups,$base" } }
    Add-ADGroupMember "IT-Admins" -Members j.perez -EA SilentlyContinue
    Add-ADGroupMember "Finance"   -Members m.lopez,a.garcia -EA SilentlyContinue
    # Señuelo Kerberoasting: svc_sql con SPN (+RC4 0x17 para el patron clasico)
    if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc_sql'" -EA SilentlyContinue)) {
        New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" -Path "OU=ServiceAccounts,$base" `
            -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true }
    Set-ADUser svc_sql -ServicePrincipalNames @{ Add = "MSSQLSvc/sql01.$((Get-ADDomain).DNSRoot):1433" } -EA SilentlyContinue
    Set-ADUser svc_sql -Replace @{ "msDS-SupportedEncryptionTypes" = 0x17 }
    # Señuelo AS-REP Roasting: a.garcia sin preautenticacion
    Set-ADAccountControl -Identity a.garcia -DoesNotRequirePreAuth $true
    Write-Output "FASE 2 OK: $(Get-ADOrganizationalUnit -Filter * -SearchBase $base | Measure-Object | % Count) OUs, señuelos creados."
} -ArgumentList $UserPass
Write-Host ">>> DC01 listo: $Domain operativo."
