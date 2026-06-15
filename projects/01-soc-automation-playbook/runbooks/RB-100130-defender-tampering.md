# 🛠️ Runbook RB-100130 — Tamper de Microsoft Defender

> **Regla(s) Wazuh:** 100130 (nivel 12) · **ATT&CK:** T1562.001 Impair Defenses (Defense Evasion) · **Severidad:** Alta (nivel 12)

## 1. Disparo

La regla **100130** dispara sobre eventos de creacion de proceso (4688) cuyo `commandLine` contiene una de estas firmas de manipulacion de Defender:

- `Add-MpPreference` / `Set-MpPreference` (modifica configuracion del motor)
- `-ExclusionPath` (anade exclusion de ruta -> Defender deja de escanear ahi)
- `DisableRealtimeMonitoring` (apaga la proteccion en tiempo real, RTP)

Origen: endpoint **WIN11** (10.10.10.21), con Sysmon + Microsoft Defender, recolectado por el agente Wazuh hacia el manager (10.10.10.20). Cualquier coincidencia es de nivel 12 porque el objetivo de la tecnica es cegar al EDR antes de ejecutar lo malicioso.

## 2. Triage inicial (objetivo: TP/FP en < 5 min)

Checklist por orden de prioridad:

1. **¿Que verbo se uso?**
   - `DisableRealtimeMonitoring` o `Set-MpPreference -DisableRealtimeMonitoring $true` -> **TP casi seguro**. No hay caso de uso legitimo en un endpoint gestionado. Escalar ya.
   - `-ExclusionPath` -> depende de la RUTA (paso 2).
2. **¿Que ruta se excluye?**
   - Rutas de usuario / volatiles = **ROJO**: `C:\Users\...`, `\AppData\`, `\Temp\`, `C:\Windows\Temp`, `C:\Users\Public`, `\Downloads\`.
   - Rutas de instalador/aplicacion legitima (`C:\Program Files\...`) pueden ser IT legitimo, pero confirmar contra baseline.
   - **Known-good del lab:** se observo `Add-MpPreference -ExclusionPath C:\soc-de-test-REMOVEME` (prueba del analista, ya revertida). Esa ruta concreta es FP conocido; cualquier otra exclusion de ruta de usuario/Temp es TP hasta demostrar lo contrario.
3. **¿Quien lo ejecuto?** Si es **CORP\Administrator** en ventana de mantenimiento conocida (PS-remoting, reinstalacion de Sysmon -> baseline de admin del Proyecto 2), baja la probabilidad. Si es `j.perez`/`m.lopez`/`helpdesk` o cuenta de servicio, sube.
4. **¿Hubo ejecucion DESDE la ruta excluida justo despues?** Exclusion + proceso lanzado desde esa misma ruta en segundos = TP de alta confianza (estaban preparando terreno).
5. **¿Hay 100160/100161 (Defender 1116/1117) cercanas en el tiempo?** Si Defender ya detecto/bloqueo algo alrededor del tamper, es TP y ademas tienes el IoC de lo que querian ocultar.

## 3. Enriquecimiento

**Local (disponible en el lab AISLADO):**

Alerta y comando exacto desde el manager:
```bash
jq 'select(.rule.id=="100130") | {ts:.timestamp, agent:.agent.name, cmd:(.data.win.eventdata.commandLine // .data.win.eventdata.scriptBlockText)}' /var/ossec/logs/alerts/alerts.json
```

Estado actual de Defender en WIN11 (PowerShell Direct desde el host):
```powershell
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, IoavProtectionEnabled, IsTamperProtected
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Get-MpThreat
```

Linaje del proceso que lanzo el comando (Sysmon EID 1 con padre + hash):
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 50 |
  Where-Object { $_.Message -match 'MpPreference|ExclusionPath|DisableRealtimeMonitoring' } |
  Format-List TimeCreated, Message
```

Quien es el usuario en AD (pertenencia a grupos, privilegio):
```powershell
Get-ADUser -Identity <usuario> -Properties MemberOf, LastLogonDate | Select-Object Name, Enabled, LastLogonDate, MemberOf
```

Correlacion con detecciones de Defender (1116/1117) alrededor del tamper:
```bash
jq 'select(.rule.id=="100160" or .rule.id=="100161") | {ts:.timestamp, agent:.agent.name, threat:.data.win.eventdata."threat Name", action:.data.win.eventdata."action Name"}' /var/ossec/logs/alerts/alerts.json
```

**Externo (CONCEPTUAL — lab sin internet):** en un SOC real, con el hash SHA256 del proceso padre/hijo y cualquier URL/IoC asociado, se haria lookup en VirusTotal / AbuseIPDB / OTX (plantilla de IoC lookup). Aqui se documenta el IoC y se deja marcado para enriquecimiento offline.

## 4. Investigacion

Preguntas a responder y pivotes:

- **Linaje:** ¿que proceso padre lanzo el `Add-MpPreference`/`Set-MpPreference`? (Sysmon EID 1 `parentImage` + `image` + SHA256). ¿PowerShell interactivo, un script, un proceso hijo de Office/navegador?
- **Usuario y privilegio:** ¿la cuenta tiene derechos para modificar Defender? ¿Es admin local/dominio? (`Get-ADUser`, `MemberOf`). Contrastar con baseline de admin conocido.
- **Temporalidad:** ¿el tamper precede a otra actividad? Pivotar al historico de 4688 en `alerts.json` (la regla base 67027 alerta en cada 4688) para ver que se ejecuto justo despues, especialmente **desde la ruta excluida**.
- **Alcance:** ¿solo WIN11 o se repite la firma en otros agentes? ¿Una sola exclusion o varias / RTP apagada de forma persistente?
- **Encadenamiento:** ¿hay 100120 (PowerShell ofuscado), 100150/151/152 (LOLBins certutil/bitsadmin/mshta) o 100160/161 (Defender caza) en la misma ventana? El tamper suele ser el paso previo a una descarga o ejecucion.

## 5. Respuesta

Proporcionada a severidad Alta (nivel 12):

1. **Revertir el tamper de inmediato** (PowerShell Direct):
   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $false
   Remove-MpPreference -ExclusionPath '<ruta_excluida>'
   ```
2. **Reactivar y verificar** RTP: `Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled` debe devolver `True`.
3. **Buscar lo que se quiso ocultar:** forzar analisis de la ruta que estaba excluida: `Start-MpScan -ScanPath '<ruta_excluida>' -ScanType CustomScan`; revisar `Get-MpThreat`.
4. **Aislar WIN11** si hay TP confirmado (red LAB ya aislada; en produccion seria contencion de red del host) y preservar evidencia antes de limpiar.
5. **Correlacionar con 100160/100161:** si Defender detecto/bloqueo algo pese al tamper, ese threat es el objetivo real — pivotar a su IoC.
6. **Escalar a IR (PICERL, Proyecto 4)** con el handoff: este playbook llega hasta la respuesta inicial.

Si es el **FP conocido** (`C:\soc-de-test-REMOVEME`, admin, ya revertido): cerrar como benigno documentando la justificacion.

## 6. Documentacion

Registrar en el caso:

- **Campos clave:** `timestamp`, `agent.name` (WIN11), `rule.id` 100130, usuario, `commandLine` completo, verbo usado (`-ExclusionPath` vs `DisableRealtimeMonitoring`), ruta excluida.
- **IoCs:** ruta excluida, SHA256 del proceso padre/hijo (Sysmon EID 1), cualquier proceso ejecutado desde la ruta excluida; threat name/action de 100160/161 si aplica.
- **Decision:** TP / FP con justificacion; estado de Defender antes y despues (RTP, exclusiones); acciones de reversion ejecutadas; si se escalo a IR.
- **ATT&CK:** T1562.001 (y tecnicas encadenadas observadas: T1059.001, T1105, etc.).

## 7. Automatizacion aplicable

Wazuh Active Response (lado-manager) ya **abre un caso automaticamente** ante toda alerta de nivel >=12, por lo que 100130 genera ticket con enriquecimiento de solo-lectura sin intervencion. Como AR lado-agente podria automatizarse la **respuesta segura**: revertir la exclusion y reactivar RTP (`Remove-MpPreference`/`Set-MpPreference -DisableRealtimeMonitoring $false`) y disparar `Start-MpScan` sobre la ruta excluida, dejando contencion/aislamiento como decision humana.