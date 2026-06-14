<#
.SYNOPSIS  Despliega el agente Wazuh en una VM Windows del lab por PowerShell Direct (sin red).
.DESCRIPTION
    1) Habilita Guest Service Interface y copia el MSI con Copy-VMFile.
    2) Instala + auto-enrola el agente contra el manager (WAZUH_MANAGER/REGISTRATION_SERVER).
    3) Anade los canales Sysmon y PowerShell/Operational a ossec.conf (Security/System ya van por defecto).
    4) Reinicia el agente.
.EXAMPLE
    .\Deploy-WazuhAgent.ps1 -VMName DC01  -User 'CORP\Administrator' -Password '<password>'
    .\Deploy-WazuhAgent.ps1 -VMName WIN11 -User 'WIN11\labadmin'     -Password '<password>'
.NOTES  Lab SOC Blue Team. Ejecutar como Administrador (Hyper-V). Manager por defecto 10.10.10.20.
#>
param(
    [Parameter(Mandatory)][string]$VMName,
    [Parameter(Mandatory)][string]$User,
    [Parameter(Mandatory)][string]$Password,
    [string]$Manager = '10.10.10.20',
    [string]$Msi     = 'C:\Lab\wazuh-agent.msi'
)
$ErrorActionPreference = 'Stop'
$cred = New-Object System.Management.Automation.PSCredential($User, (ConvertTo-SecureString $Password -AsPlainText -Force))

Write-Output "[*] Abriendo PSSession por PowerShell Direct..."
$sess = New-PSSession -VMName $VMName -Credential $cred
Write-Output "[*] Copiando MSI por VMBus (Copy-Item -ToSession, sin Guest Service Interface)..."
Copy-Item -ToSession $sess -Path $Msi -Destination 'C:\Windows\Temp\wazuh-agent.msi' -Force

Write-Output "[*] Instalar + enrolar + canales..."
Invoke-Command -Session $sess -ArgumentList $Manager, $VMName -ScriptBlock {
    param($mgr, $name)
    $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList `
        "/i C:\Windows\Temp\wazuh-agent.msi /q WAZUH_MANAGER=$mgr WAZUH_REGISTRATION_SERVER=$mgr WAZUH_AGENT_NAME=$name"
    "msiexec_exit=$($p.ExitCode)"
    $cfg = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
    $add = "  <localfile><location>Microsoft-Windows-Sysmon/Operational</location><log_format>eventchannel</log_format></localfile>`r`n" +
           "  <localfile><location>Microsoft-Windows-PowerShell/Operational</location><log_format>eventchannel</log_format></localfile>`r`n"
    $c = Get-Content $cfg -Raw
    if ($c -notmatch 'Sysmon/Operational') {
        $c = $c -replace '</ossec_config>', ($add + '</ossec_config>')
        [System.IO.File]::WriteAllText($cfg, $c, (New-Object System.Text.UTF8Encoding($false)))
        "eventchannels=added"
    } else { "eventchannels=already-present" }
    Start-Sleep 2
    Restart-Service WazuhSvc -ErrorAction SilentlyContinue
    Start-Sleep 3
    "WazuhSvc=" + (Get-Service WazuhSvc).Status
}
Remove-PSSession $sess
Write-Output "[+] Agente desplegado en $VMName (manager $Manager)."
