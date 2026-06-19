<#
.SYNOPSIS
    Despliega el ruleset (incluidas las reglas de Akira del P6) en el manager Wazuh y lo valida
    con la simulación benigna, en UN SOLO comando. Ejecutar en el HOST, PowerShell ELEVADA.
.DESCRIPTION
    Pasos (con rollback seguro):
      [0] Checkpoint de DC01 y WIN11 (por si algo falla, revertir).
      [1] Copia wazuh/rules/local_rules.xml al manager (scp), valida la carga (wazuh-logtest -t)
          y reinicia el manager.
      [2] Lanza Invoke-AkiraSimulation.ps1 (recon real de solo-lectura + marcadores benignos).
      [3] Recoge del manager las alertas de las reglas nuevas + los casos del Active Response.
    Requisitos: cliente OpenSSH en el host (ssh/scp), credenciales SSH del manager (se piden),
    DC01 + WIN11 + WAZUH encendidas. NADA destructivo: la simulación solo hace recon y 'echo'.
.PARAMETER ManagerIp  IP del manager Wazuh en LAB-Net (def. 10.10.10.20).
.PARAMETER SshUser    Usuario SSH del manager (si se omite, se pregunta).
.PARAMETER Pass       Password de las cuentas del lab para PowerShell Direct (def. Lab.Admin.2026!).
.NOTES  Lab SOC Blue Team (corp.local). Derivado del CTI de Akira (CISA AA24-109A).
#>
param(
    [string]$ManagerIp = "10.10.10.20",
    [string]$SshUser   = "",
    [string]$Pass      = "Lab.Admin.2026!"
)
$ErrorActionPreference = "Stop"

if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    throw "No se encontró el cliente OpenSSH (ssh). Instálalo: Settings > Apps > Optional Features > OpenSSH Client."
}
$repo  = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # ...\SOC-Blue-Team
$rules = Join-Path $repo "wazuh\rules\local_rules.xml"
if (-not (Test-Path $rules)) { throw "No existe el ruleset: $rules" }
if (-not $SshUser) { $SshUser = Read-Host "Usuario SSH del manager Wazuh ($ManagerIp)" }
$mgr = "${SshUser}@${ManagerIp}"

Write-Host "==> [0] Checkpoints de seguridad (DC01, WIN11)" -ForegroundColor Cyan
foreach ($vm in 'DC01','WIN11') {
    try   { Checkpoint-VM -Name $vm -SnapshotName "pre-akira-deploy_$(Get-Date -Format yyyyMMddHHmm)" -ErrorAction Stop; "    checkpoint $vm OK" }
    catch { Write-Warning "checkpoint $vm: $($_.Exception.Message)" }
}

Write-Host "==> [1] Subiendo el ruleset al manager y recargando" -ForegroundColor Cyan
scp $rules "${mgr}:/tmp/local_rules.xml"
$deploy = @'
sudo cp /tmp/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
if sudo /var/ossec/bin/wazuh-logtest -t; then echo "RULESET_OK"; else echo "RULESET_FAIL"; exit 1; fi
sudo systemctl restart wazuh-manager
sleep 8; echo "manager: $(systemctl is-active wazuh-manager)"
'@
ssh $mgr $deploy

Write-Host "==> [2] Lanzando la simulación benigna de TTPs de Akira (WIN11)" -ForegroundColor Cyan
& (Join-Path $PSScriptRoot "Invoke-AkiraSimulation.ps1") -Pass $Pass

Write-Host "==> [3] Esperando ingesta y recogiendo alertas del manager" -ForegroundColor Cyan
Start-Sleep -Seconds 15
$verify = @'
echo "=== Alertas de reglas derivadas de Akira (ultimas 40) ==="
sudo grep -hE '"id":"(100181|100190|100191|100200|100210|100211|100220|100230)"' /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -n 40
echo ""
echo "=== Casos SOC abiertos por Active Response (ultimos 20) ==="
sudo tail -n 20 /var/ossec/logs/soc-cases.log 2>/dev/null
'@
ssh $mgr $verify
Write-Host "==> Hecho. Compara con evidence/deployment-and-validation.md (tabla 'resultados esperados')." -ForegroundColor Green
Write-Host "    Si algo no dispara: dashboard Wazuh > Events > expandir el evento > revisar data.win.eventdata.* (afinado de campos)."
