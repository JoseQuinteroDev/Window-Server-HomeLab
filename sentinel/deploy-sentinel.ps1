<#
.SYNOPSIS  Despliega el SIEM del lab: Resource Group + Log Analytics workspace + onboarding de Microsoft Sentinel.
.DESCRIPTION
    Requiere 'az login' hecho (suscripcion Azure activa). Idempotente en lo posible.
    Tras esto, desplegar las reglas con analytics-rules.json (ver README).
.NOTES  Lab SOC Blue Team. Coste: borra el RG al terminar (az group delete -n <rg>) para no acumular gasto.
#>
param(
    [string]$ResourceGroup = "rg-soc-lab",
    [string]$Location      = "westeurope",
    [string]$Workspace     = "law-soc-lab",
    [int]   $RetentionDays = 90
)
$ErrorActionPreference = "Stop"

Write-Host ">>> Comprobando sesion az..."
az account show -o table
if ($LASTEXITCODE -ne 0) { throw "No hay sesion az. Ejecuta primero:  az login" }

Write-Host ">>> Registrando proveedores necesarios..."
az provider register --namespace Microsoft.OperationalInsights --wait
az provider register --namespace Microsoft.SecurityInsights --wait

Write-Host ">>> Resource group $ResourceGroup ($Location)..."
az group create -n $ResourceGroup -l $Location -o table

Write-Host ">>> Log Analytics workspace $Workspace..."
az monitor log-analytics workspace create `
    -g $ResourceGroup -n $Workspace -l $Location `
    --retention-time $RetentionDays -o table

$wsId = az monitor log-analytics workspace show -g $ResourceGroup -n $Workspace --query id -o tsv

Write-Host ">>> Onboarding de Microsoft Sentinel sobre el workspace..."
az extension add -n sentinel --only-show-errors 2>$null
az sentinel onboarding-state create -g $ResourceGroup --workspace-name $Workspace -n default --only-show-errors
if ($LASTEXITCODE -ne 0) {
    Write-Host "   (CLI fallback) Habilitando Sentinel via solucion SecurityInsights..."
    az deployment group create -g $ResourceGroup --template-uri "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Tools/Sentinel-All-In-One/onboarding.json" --parameters workspaceName=$Workspace 2>$null
}

Write-Host ""
Write-Host "================ HECHO ================"
Write-Host "Workspace ID: $wsId"
Write-Host "Siguiente: desplegar reglas analiticas ->"
Write-Host "   az deployment group create -g $ResourceGroup --template-file .\analytics-rules.json --parameters workspaceName=$Workspace"
Write-Host "Conectar telemetria del lab -> connect-lab-runbook.md"
Write-Host "Al terminar (evitar gasto):  az group delete -n $ResourceGroup --yes --no-wait"
