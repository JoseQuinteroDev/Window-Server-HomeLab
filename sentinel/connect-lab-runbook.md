# 🔌 Conectar la telemetría del lab aislado a Sentinel

El lab vive en `LAB-Net` (Internal, **sin internet**). Para llevar sus logs a Sentinel hay que dar
salida temporal a las VMs y onboardearlas. Dos caminos (puedes hacer ambos):

---

## Camino A — Azure Arc + Azure Monitor Agent (para Sentinel)

Lleva **Security events + Sysmon + PowerShell** de DC01/WIN11 a Log Analytics → Sentinel.

### A.0 — Internet temporal para las VMs *(lo hace Claude en el host)*
```powershell
# Anadir un 2o adaptador con salida a internet (Default Switch = NAT de Hyper-V)
Add-VMNetworkAdapter -VMName WIN11 -SwitchName 'Default Switch'
Add-VMNetworkAdapter -VMName DC01  -SwitchName 'Default Switch'
# (dentro de la VM el adaptador coge IP por DHCP del Default Switch)
# >>> QUITARLO al terminar el onboarding para volver al aislamiento:
# Remove-VMNetworkAdapter -VMName WIN11 -Name 'Network Adapter' ...
```
> ⚠️ Regla de oro del lab: el DC **nunca** debe quedar con internet permanente. Es solo para el onboarding.

### A.1 — Onboard a Azure Arc (dentro de cada VM, o por script)
`portal.azure.com → Azure Arc → Servers → Add → Generate script` → ejecutar el script en la VM
(instala el *Connected Machine agent* y hace `azcmagent connect`). Requiere la suscripcion del paso de cuenta.

### A.2 — Data Collection Rule (DCR) + AMA
En el portal: **Monitor → Data Collection Rules → Create**, asociar las máquinas Arc, y añadir orígenes:
- **Windows Event Logs**:
  - `Security!*[System[(EventID=4688 or EventID=4624 or EventID=4625 or EventID=4768 or EventID=4769 or EventID=4720)]]`
  - `Microsoft-Windows-Sysmon/Operational!*`
  - `Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4104)]]`
- Destino: el workspace `law-soc-lab`. El AMA se instala solo al asociar la DCR.

### A.3 — Verificar
En Sentinel → Logs:
```kql
SecurityEvent | summarize count() by EventID | sort by count_ desc
Event | where Source in ('Microsoft-Windows-Sysmon','Microsoft-Windows-PowerShell') | summarize count() by EventID
```
Cuando aparezcan datos, **re-ejecuta** `projects/03-detection-engineering/tests/Invoke-DetectionTests.ps1`
y comprueba que las **reglas analíticas** generan incidentes en Sentinel.

---

## Camino B — Defender XDR / Defender for Endpoint (alternativa para endpoints)

Más simple para WIN11 (no necesita Arc/DCR), usa el tenant E5:
1. `security.microsoft.com → Settings → Endpoints → Onboarding → Windows 10/11 → Local Script` → ejecutar en WIN11.
2. Hunting con las variantes KQL `DeviceProcessEvents` de [`../projects/03-detection-engineering/kql/detections.kql`](../projects/03-detection-engineering/kql/detections.kql).

> Defender XDR cubre endpoint (procesos, cmdline). Para eventos Kerberos del DC (4769/4768) sigue siendo
> mejor el Camino A (Sentinel + Security events del DC).

---

## ✅ Al terminar — evitar gasto y restaurar aislamiento
```powershell
Remove-VMNetworkAdapter -VMName WIN11 -SwitchName 'Default Switch'   # quitar internet
Remove-VMNetworkAdapter -VMName DC01  -SwitchName 'Default Switch'
# y en Azure, si era solo una prueba:
az group delete -n rg-soc-lab --yes --no-wait
```
