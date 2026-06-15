# Runbook RB-100160 — Deteccion/accion de Microsoft Defender (EDR como pista)

> **Regla(s) Wazuh:** 100160 (EID 1116, deteccion) · 100161 (EID 1117, accion) · **ATT&CK:** EDR como fuente de verdad / pivote de caza (no es una tecnica del adversario; es deteccion del defensor que apunta a la tecnica subyacente) · **Severidad:** Alta (nivel 12 en la deteccion 1116; nivel 10 en la accion 1117)

## 1. Disparo

La alerta se origina en el endpoint WIN11 (10.10.10.21), canal `Microsoft-Windows-Windows Defender/Operational`:

- **100160** dispara con **EID 1116** (Microsoft Defender DETECTO malware/amenaza). Nivel 12.
- **100161** dispara con **EID 1117** (Microsoft Defender ACCIONO: bloqueo, cuarentena o limpieza). Nivel 10.

Condicion exacta: la regla evalua `win.system.channel` = canal Defender/Operational y `win.system.eventID` 1116 / 1117. Los campos de amenaza llegan con **espacio** en el nombre (peculiaridad de Defender): `win.eventdata."threat Name"` y `win.eventdata."action Name"`.

**Caso de referencia del lab:** `Trojan:Win32/Ceprolad.A` (ThreatID `2147726914`), que correspondio al `certutil -urlcache` (ver regla 100150, LOLBin), detectado y **bloqueado**. Defensa en profundidad: la regla del LOLBin (100150) y la de Defender (100160/100161) disparan sobre el mismo incidente desde fuentes distintas.

## 2. Triage inicial (objetivo: TP/FP en < 5 min)

> **Premisa:** 1116/1117 son **TP por definicion** — el EDR ya confirmo malware. El triage NO decide si hay amenaza (la hay); decide **el ALCANCE** y si el bloqueo fue completo.

Checklist:

1. **Leer `threat Name` y `action Name`.** Identifica la familia (p. ej. `Trojan:Win32/Ceprolad.A`) y si la accion fue contencion efectiva (`Quarantine`, `Remove`, `Block`) o solo deteccion sin remediacion exitosa (`Allowed`, `Not Applicable` -> bandera roja: malware NO contenido).
2. **¿Hubo 1116 sin su 1117?** Una deteccion sin accion de remediacion es prioridad maxima: el binario pudo ejecutarse. Buscar el par.
3. **¿Que proceso/ruta?** El recurso/proceso afectado en el evento -> ¿es una ruta de usuario (`C:\Users\...`, `%TEMP%`) o de sistema?
4. **Correlacion con otras reglas en la misma ventana:** ¿disparo tambien 100150/100151/100152 (LOLBin), 100120 (PS ofuscado) o 100130 (tamper de Defender) en +/- unos minutos? Un **tamper previo (100130)** a la deteccion sugiere intento de evadir justo este bloqueo.
5. **Known-good del lab:** el baseline de admin (PS-remoting, reinstalacion de Sysmon) NO genera detecciones de Defender. Una deteccion 1116/1117 **no tiene equivalente benigno conocido** -> no se descarta como ruido de admin.

**Veredicto:** TP confirmado. Pasa a determinar alcance (seccion 4).

## 3. Enriquecimiento

**Local — Wazuh (jq sobre `/var/ossec/logs/alerts/alerts.json`):**

```bash
# Detecciones y acciones de Defender, con familia, accion y host
jq -r 'select(.rule.id=="100160" or .rule.id=="100161")
  | [.timestamp, .rule.id, .agent.name,
     .data.win.eventdata."threat Name",
     .data.win.eventdata."action Name"] | @tsv' \
  /var/ossec/logs/alerts/alerts.json
```

```bash
# Pivote temporal: TODO lo del agente WIN11 alrededor del bloqueo (ajustar fecha)
jq -r 'select(.agent.name=="WIN11" and (.timestamp|startswith("2026-06-15T14")))
  | [.timestamp, .rule.id, .rule.description] | @tsv' \
  /var/ossec/logs/alerts/alerts.json
```

```bash
# ¿Hubo tamper de Defender (100130) el mismo dia? Intento de evadir el bloqueo
jq -r 'select(.rule.id=="100130")
  | [.timestamp, .agent.name, .data.win.eventdata.commandLine] | @tsv' \
  /var/ossec/logs/alerts/alerts.json
```

**Local — endpoint (PowerShell Direct desde el host, sin red):**

```powershell
# Estado del motor/firmas y proteccion en tiempo real
Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated

# Historico de amenazas detectadas (familia, ruta, accion, recurso)
Get-MpThreat
Get-MpThreatDetection | Select-Object ThreatID, ActionSuccess, ProcessName, Resources, InitialDetectionTime
```

```powershell
# Log crudo de Defender (deteccion + accion) en la ventana del incidente
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117
} -MaxEvents 20 | Format-List TimeCreated, Id, Message
```

**Externo (CONCEPTUAL — lab aislado, sin internet):** en un SOC real se haria lookup del `threat Name` y del hash SHA256 del binario afectado en VirusTotal / OTX / Microsoft Security Intelligence para confirmar familia, TTPs asociadas y prevalencia. Aqui se documenta en la **plantilla de IoC lookup** sin ejecucion online.

## 4. Investigacion

Preguntas a responder y pivotes (la deteccion es la **pista**, no el final):

- **¿Que proceso disparo la deteccion?** Pivote a **linaje de proceso** via Sysmon EID 1 (`win.eventdata.image`, `parentImage`, hash SHA256) y a `4688` / regla base 67027 (`win.eventdata.newProcessName`, `commandLine`) en +/- la ventana del bloqueo.

```bash
# Procesos creados en WIN11 cerca del bloqueo (4688) — linaje y linea de comandos
jq -r 'select(.agent.name=="WIN11" and .data.win.system.eventID=="4688")
  | [.timestamp, .data.win.eventdata.newProcessName,
     .data.win.eventdata.commandLine] | @tsv' \
  /var/ossec/logs/alerts/alerts.json
```

```powershell
# Linaje + hash desde Sysmon en el endpoint
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 50 |
  Where-Object { $_.Message -match 'certutil|Ceprolad|\\Temp\\|\\Users\\' } |
  Format-List TimeCreated, Message
```

- **¿Que usuario?** Identificar la cuenta del proceso y enriquecer con AD:

```powershell
Get-ADUser -Identity <usuario> -Properties MemberOf, LastLogonDate, Enabled |
  Select-Object SamAccountName, Enabled, LastLogonDate, MemberOf
```

- **¿Temporalidad / alcance?** ¿Es un evento aislado o parte de una cadena? ¿Hubo descarga (LOLBin 100150-100152), ejecucion ofuscada (100120) o tamper (100130) antes? ¿La deteccion afecto a un solo host o aparece el mismo `threat Name` en otros agentes?
- **¿El bloqueo fue completo?** Confirmar con `Get-MpThreatDetection` que `ActionSuccess=True` y que no quedan recursos en `Pending`. Una variante o una copia en otra ruta que NO disparo es el riesgo residual a cazar.

## 5. Respuesta

Acciones proporcionadas a severidad Alta:

1. **Confirmar contencion.** Verificar en `Get-MpThreatDetection`/`Get-MpThreat` que la accion fue exitosa (`Quarantine`/`Remove`, `ActionSuccess=True`). Defender ya bloqueo, pero **no asumir** — validar que no hubo una variante o ejecucion previa que pasara desapercibida.
2. **Si hay indicios de ejecucion exitosa** (1116 sin 1117, ruta de usuario con escritura, proceso hijo sospechoso, o tamper 100130 previo): tratar el host como potencialmente comprometido. **Aislar WIN11** (en el lab: desconectar el adaptador virtual / detener la VM via PowerShell Direct desde el host) y preservar evidencia.
3. **Erradicacion inicial:** confirmar cuarentena del binario; si quedaron artefactos (copia en otra ruta, tarea programada, servicio 7045 -> candidata 100170), eliminarlos. La erradicacion profunda es del **Proyecto 4 (IR/PICERL)**.
4. **Escalar a IR** con el paquete de evidencia (seccion 6). Este runbook llega a la **respuesta inicial y handoff**; contencion/erradicacion/recuperacion completas se ejecutan en el flujo PICERL.

## 6. Documentacion

Registrar en el caso:

- **Identificadores:** rule.id (100160 / 100161), EID (1116 / 1117), `threat Name` (`Trojan:Win32/Ceprolad.A`), ThreatID (`2147726914`), `action Name` y resultado (exitoso/fallido).
- **Host y usuario:** agente (WIN11, 10.10.10.21), cuenta del proceso, pertenencia a grupos (AD).
- **IoCs:** ruta/nombre del fichero, SHA256 del binario (Sysmon EID 1), proceso padre, linea de comandos (4688), familia de malware.
- **Cadena de eventos:** reglas correlacionadas en la ventana (100150/100120/100130, etc.) y timeline.
- **Decision:** TP confirmado por el EDR; alcance determinado; contencion verificada SI/NO; aislamiento aplicado SI/NO; escalado a IR SI/NO. Marcar IoCs pendientes de lookup externo en la plantilla.

## 7. Automatizacion aplicable

Wazuh Active Response (lado-manager) ya **abre un caso automaticamente** ante alertas de nivel >=12, por lo que la deteccion 1116 (nivel 12) genera ticket con enriquecimiento de solo-lectura sin intervencion. Es automatizable ademas el **pivote temporal** (consulta jq parametrizada por `agent.name` y ventana) y la **comprobacion de estado** (`Get-MpComputerStatus`/`Get-MpThreatDetection`) como acciones de enriquecimiento seguras; el aislamiento del host se deja como decision humana por su impacto.