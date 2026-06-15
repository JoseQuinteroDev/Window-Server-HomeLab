# Hunt H3 — Evasion de defensas: tamper de Defender + el EDR como pista de caza

> Tactica ATT&CK **Defense Evasion** (TA0005) - Tecnica **T1562.001 — Impair Defenses: Disable or Modify Tools**.

## Hipotesis

Un atacante que ya ejecuta codigo en WIN11 intentara **cegar a Defender antes de detonar su payload**: anadir una exclusion de ruta (`Add-MpPreference -ExclusionPath`) o apagar la proteccion en tiempo real (`-DisableRealtimeMonitoring`) para que el binario malicioso corra en una carpeta "ciega". Como corolario de caza: si Defender **bloqueo** algo (1116/1117), ese bloqueo no es el final de la historia, sino el **punto de partida** para investigar que intentaba hacer el atacante alrededor.

## Tecnica ATT&CK

**T1562.001 — Disable or Modify Tools** (tactica Defense Evasion, TA0005). El adversario manipula los controles de seguridad del host en vez de sortearlos: modifica la configuracion de Defender via el modulo PowerShell `Defender` (`Set-MpPreference` / `Add-MpPreference`), anade exclusiones de ruta/proceso/extension, o desactiva el motor de proteccion en tiempo real. El efecto es que el AV sigue "encendido" en apariencia, pero deja de inspeccionar la zona elegida — el malware ejecuta sin generar deteccion.

## Fuente de datos

Dos fuentes complementarias, una para el **tamper** y otra como **verdad de terreno** del EDR:

- **Tamper (la accion del atacante):** `Security` **4688** (`win.eventdata.newProcessName` + `win.eventdata.commandLine`) y `Microsoft-Windows-Sysmon/Operational` **EID 1** (`win.eventdata.image` + `win.eventdata.commandLine`). La **linea de comandos** (`win.eventdata.commandLine`) es comun a ambos sensores -> es el campo preferido para cazar la ejecucion de forma agnostica del sensor. Refuerzo: `Microsoft-Windows-PowerShell/Operational` **4104** (Script Block Logging, `win.eventdata.scriptBlockText`) por si el `Add-MpPreference` viene ofuscado.
- **Verdad del EDR (que vio Defender):** `Microsoft-Windows-Windows Defender/Operational` **1116** (deteccion) y **1117** (accion tomada). Estos eventos **no llegaban al SIEM** hasta que se ingirio el canal Defender en el agente Wazuh — sin ellos, el SOC era ciego a las propias decisiones del antivirus del endpoint. OJO con los nombres de campo: los eventos de Defender conservan **espacios y mayusculas internas** (`win.eventdata."threat Name"`, `win.eventdata."action Name"`), a diferencia del resto de eventdata que va en minuscula inicial.

## La caza

### Wazuh (alerts.json, jq en el manager)

La base 67027 alerta en cada 4688 (nivel 3), asi que `alerts.json` contiene de facto **todo** el historico de creacion de procesos de WIN11. Cazamos sobre el campo agnostico `commandLine`.

> Nota de robustez: `alerts.json` mezcla EID que **no** tienen `commandLine` (4624, 4769, 1116, FileCreate, etc.). Aplicar `test()` directamente sobre un campo `null` aborta el stream de jq. Por eso usamos el guard `// ""` (alternativa null) antes de `test()`.

```bash
# (1) Tamper de Defender: exclusiones o desactivacion de RTP (4688 + Sysmon EID 1)
jq -c 'select((.data.win.eventdata.commandLine // "")
        | test("Add-MpPreference|-ExclusionPath|DisableRealtimeMonitoring|Set-MpPreference"; "i"))
       | {ts: .timestamp, rule: .rule.id, lvl: .rule.level,
          chan: .data.win.system.channel, eid: .data.win.system.eventID,
          cmd: .data.win.eventdata.commandLine}' \
  /var/ossec/logs/alerts/alerts.json

# (2) El EDR como pista de caza: TODA deteccion/accion de Defender (1116/1117)
#     OJO: los campos de Defender conservan ESPACIOS y mayusculas internas.
jq -c 'select(.data.win.system.channel=="Microsoft-Windows-Windows Defender/Operational"
        and (.data.win.system.eventID=="1116" or .data.win.system.eventID=="1117"))
       | {ts: .timestamp, rule: .rule.id, eid: .data.win.system.eventID,
          threat: .data.win.eventdata."threat Name",
          action: .data.win.eventdata."action Name"}' \
  /var/ossec/logs/alerts/alerts.json

# (3) Pivote temporal: tomado el ts de un bloqueo 1116/1117, ¿que procesos
#     corrieron en WIN11 en esa ventana? Sustituye TS_INI / TS_FIN por el rango
#     (p.ej. +/- 5 min alrededor del bloqueo, en formato ISO del .timestamp).
jq -c --arg ini "TS_INI" --arg fin "TS_FIN" '
       select((.data.win.system.eventID=="4688" or .data.win.system.eventID=="1")
         and .timestamp >= $ini and .timestamp <= $fin)
       | {ts: .timestamp, eid: .data.win.system.eventID,
          cmd: .data.win.eventdata.commandLine}' \
  /var/ossec/logs/alerts/alerts.json
```

### Origen — logs crudos (PowerShell Direct, Get-WinEvent)

Metodologia: la caza mira la telemetria **cruda** en origen, no solo lo que ya disparo una regla. Via PowerShell Direct desde el host Hyper-V hacia WIN11.

```powershell
# Tamper en crudo: 4688 (Security) + EID 1 (Sysmon) con la firma de Add-MpPreference / RTP
$rx = 'Add-MpPreference|ExclusionPath|DisableRealtimeMonitoring|Set-MpPreference'
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688 } |
  Where-Object { $_.Message -match $rx } |
  Select-Object TimeCreated, Id, @{n='Cmd';e={ ($_.Message -split "`n" | Select-String 'Command Line') }}

Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=1 } |
  Where-Object { $_.Message -match $rx } |
  Select-Object TimeCreated, Id, Message

# Verdad del EDR en crudo: detecciones (1116) y acciones (1117) de Defender
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117 } |
  Select-Object TimeCreated, Id, Message
```

### KQL (Sentinel / Defender XDR — equivalente teorico)

No se ejecuta en el lab (corre Wazuh); se incluye como se veria en un SIEM cloud.

```kql
// Tamper de Defender — DeviceProcessEvents (EDR)
DeviceProcessEvents
| where ProcessCommandLine has_any
    ("Add-MpPreference", "-ExclusionPath", "DisableRealtimeMonitoring", "Set-MpPreference")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc

// Verdad del EDR — detecciones y acciones de Defender via DeviceEvents
DeviceEvents
| where ActionType == "AntivirusDetection"
| project Timestamp, DeviceName, FileName, FolderPath, AdditionalFields
| order by Timestamp desc
```

## Hallazgos (datos del lab)

| # | Que se observo | Evento / canal | Regla Wazuh | Estado |
|---|----------------|----------------|-------------|--------|
| 1 | `Add-MpPreference -ExclusionPath C:\soc-de-test-REMOVEME` (tamper de exclusion) | 4688 / Sysmon EID 1 (`commandLine`) | **100130** (nivel 12) | Revertido tras la prueba |
| 2 | Defender **detecto** el `certutil -urlcache` y lo clasifico como **`Trojan:Win32/Ceprolad.A`** (ThreatID 2147726914) | **1116** (deteccion) - canal Defender/Operational | **100160** | Bloqueado por el EDR |
| 3 | Defender **tomo accion** (bloqueo) sobre la misma amenaza | **1117** (accion tomada) - canal Defender/Operational | **100161** | Accion ejecutada |
| 4 | El mismo `certutil` que Defender bloqueo **tambien** disparo nuestra propia regla LOLBin | 4688 (`commandLine`) | **100150** | Defensa en profundidad |

> Nota de verificacion: el nombre de amenaza **`Trojan:Win32/Ceprolad.A`** (ThreatID **2147726914**) se confirmo en vivo con `Get-MpThreat` en WIN11 y aparece en el campo `"threat Name"` del evento 1116 (detalle en [`evidence/hunt-findings.md`](../evidence/hunt-findings.md)).

Lectura: la **misma** accion de `certutil` genero *dos* senales independientes — la regla propia **100150** (caza LOLBin por linea de comandos) **y** las de Defender **100160/100161** (verdad del EDR). Defensa en profundidad funcionando: si una capa hubiera fallado, la otra cubria.

## Triage: known-good vs malicioso

- **¿Quien y donde?** `Add-MpPreference -ExclusionPath` es legitimo en manos de IT/instaladores (algunos productos se autoexcluyen). El de la prueba (`C:\soc-de-test-REMOVEME`) es claramente de laboratorio por el nombre — **known-good de test, no de produccion**. Senales reales de malicia: exclusion de rutas de usuario (`C:\Users\...\AppData`, `Temp`, `Public`), proceso padre anomalo (Office, `mshta`, `wscript` lanzando PowerShell), o exclusion **inmediatamente seguida** de ejecucion desde esa misma ruta.
- **El cero-falso-positivo:** `DisableRealtimeMonitoring` **no** tiene casi caso de uso legitimo en un endpoint gestionado -> tratalo como malicioso por defecto.
- **El bloqueo del EDR es una pista, no un cierre:** un 1116/1117 no significa "incidente resuelto". Significa "**aqui paso algo** — pivota a esa ventana temporal" (query jq #3): que proceso lanzo el `certutil`, que descargaba la URL, si hubo intentos previos de tamper para evadir justo ese bloqueo. Defender gano *esta* ronda; el trabajo del cazador es confirmar que no hubo una variante que *si* paso.

## Outcome

- **Cobertura de tamper:** la regla **100130** (nivel 12) caza el `Add-MpPreference -ExclusionPath` / `DisableRealtimeMonitoring` por `commandLine`, agnostica del sensor (4688 o Sysmon EID 1).
- **El EDR ahora alimenta el SIEM:** ingerir el canal `Microsoft-Windows-Windows Defender/Operational` habilito las reglas nuevas **100160** (1116, deteccion) y **100161** (1117, accion). Antes de esto, las decisiones del propio antivirus del endpoint eran invisibles para el SOC.
- **Defensa en profundidad validada:** una sola ejecucion de `certutil` disparo **100150** (regla propia LOLBin) *y* **100160/100161** (Defender) — dos detecciones independientes sobre el mismo evento.
- **Leccion de metodologia:** un bloqueo de Defender (1116/1117) es una **pista de caza de altisima senal**. Operacionalizar: cada 1116/1117 abre un pivote temporal automatico a los 4688/EID 1 de ese host en la ventana del evento.