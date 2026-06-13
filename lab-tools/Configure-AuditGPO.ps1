<#
.SYNOPSIS
    Crea/actualiza la GPO 'Audit-Baseline' (auditoria avanzada + cmdline en 4688 + PowerShell logging)
    y la enlaza al dominio. Es el nucleo de telemetria Blue Team (FASE 4 de LAB-BUILD).
.DESCRIPTION
    Se ejecuta EN DC01 (requiere modulos GroupPolicy + ActiveDirectory y acceso a SYSVOL).
    - Politicas de registro (Set-GPRegistryValue): linea de comandos en 4688 + PowerShell SBL/Module/Transcription.
    - Auditoria avanzada via audit.csv en SYSVOL + registro del CSE de auditoria en gPCMachineExtensionNames
      (es exactamente lo que hace GPMC por debajo).
    Eventos resultantes: 4688(+cmdline), 4624/4625, 4769 (Kerberoasting), 4768/4771 (AS-REP), 4720/4724/4738, 4104.
.NOTES  Lab SOC Blue Team. Ejecutar como CORP\Administrator en DC01.
#>
$ErrorActionPreference = 'Stop'
Import-Module GroupPolicy
Import-Module ActiveDirectory

$gpoName = 'Audit-Baseline'
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if (-not $gpo) { $gpo = New-GPO -Name $gpoName -Comment 'Blue Team: auditoria avanzada + cmdline 4688 + PowerShell logging' }

# ---- 1) Politicas basadas en registro ----
# 4688: incluir la linea de comandos del proceso
Set-GPRegistryValue -Name $gpoName -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ValueName 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1 | Out-Null
# PowerShell Script Block Logging (4104)
Set-GPRegistryValue -Name $gpoName -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ValueName 'EnableScriptBlockLogging' -Type DWord -Value 1 | Out-Null
# PowerShell Module Logging (todos los modulos)
Set-GPRegistryValue -Name $gpoName -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ValueName 'EnableModuleLogging' -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $gpoName -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -ValueName '*' -Type String -Value '*' | Out-Null
# PowerShell Transcription a C:\PSLogs
Set-GPRegistryValue -Name $gpoName -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ValueName 'EnableTranscripting' -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $gpoName -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ValueName 'EnableInvocationHeader' -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $gpoName -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ValueName 'OutputDirectory' -Type String -Value 'C:\PSLogs' | Out-Null

# ---- 2) Auditoria avanzada via audit.csv en SYSVOL ----
$domain = (Get-ADDomain).DNSRoot
$domDN  = (Get-ADDomain).DistinguishedName
$guid   = $gpo.Id.ToString('B').ToUpper()
$auditDir = "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Microsoft\Windows NT\Audit"
New-Item -ItemType Directory -Force -Path $auditDir | Out-Null
$csv = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Audit Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Kerberos Service Ticket Operations,{0cce9240-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Kerberos Authentication Service,{0cce9242-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit User Account Management,{0cce9235-69ae-11d9-bed3-505054503030},Success,,1
'@
Set-Content -Path "$auditDir\audit.csv" -Value $csv -Encoding ASCII

# ---- 3) Registrar el CSE de auditoria en gPCMachineExtensionNames ----
$gpoDN = "CN=$guid,CN=Policies,CN=System,$domDN"
$auditCSE = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FB2}]'
$cur = (Get-ADObject -Identity $gpoDN -Properties gPCMachineExtensionNames).gPCMachineExtensionNames
if (-not $cur) { $cur = '' }
if ($cur -notlike '*F3CCC681*') {
    Set-ADObject -Identity $gpoDN -Replace @{ gPCMachineExtensionNames = ($cur + $auditCSE) }
}

# ---- 4) Enlazar al dominio ----
$linked = (Get-GPInheritance -Target $domDN).GpoLinks | Where-Object { $_.DisplayName -eq $gpoName }
if (-not $linked) { New-GPLink -Name $gpoName -Target $domDN -LinkEnabled Yes | Out-Null }

# ---- Resumen ----
"== GPO '$gpoName' (Id $($gpo.Id)) =="
"Registry: ProcessCreationIncludeCmdLine + PowerShell SBL/Module/Transcription"
"audit.csv: $auditDir\audit.csv"
"gPCMachineExtensionNames: $((Get-ADObject -Identity $gpoDN -Properties gPCMachineExtensionNames).gPCMachineExtensionNames)"
"Enlazado a: $domDN"
