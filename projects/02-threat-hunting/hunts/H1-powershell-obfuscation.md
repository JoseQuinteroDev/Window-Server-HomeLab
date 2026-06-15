# 🔎 Hunt H1 — PowerShell ofuscado / cradles de ejecución

> **Táctica:** Execution (TA0002) — y de forma secundaria **Defense Evasion (TA0005)**.
> **Técnicas:** **T1059.001** (Command and Scripting Interpreter: PowerShell, *Execution*) + **T1027** (Obfuscated Files or Information, *Defense Evasion*).
> **Lab:** `corp.local` · objetivo **WIN11** (10.10.10.21) · SIEM **Wazuh 4.13.1** (manager 10.10.10.20) · red LAB-Net aislada.

## Hipótesis

Un atacante ejecuta PowerShell ofuscado en **WIN11** para evadir detección estática: comandos `-EncodedCommand` (Base64) o *download cradles* en memoria (`IEX (New-Object Net.WebClient).DownloadString(...)`) que descargan y ejecutan payloads sin tocar disco. Como el **Script Block Logging (4104)** reconstruye el script **ya desofuscado** en `scriptBlockText`, la huella del payload debe quedar ahí aunque la línea de comandos llegue codificada en `-EncodedCommand`.

## Técnica ATT&CK

- **T1059.001 — PowerShell (Execution):** los adversarios abusan de PowerShell por su acceso nativo a la API de Windows y .NET. El binario en disco es legítimo (`powershell.exe`), así que la detección eficaz vive en el **contenido del scriptblock**, no en el nombre del proceso.
- **T1027 — Obfuscated Files or Information (Defense Evasion):** para evadir AV/EDR codifican el comando en Base64 (`powershell -enc <...>`), concatenan/reordenan cadenas, o ejecutan *cradles* fileless con `Invoke-Expression`/`IEX` sobre contenido traído por `Net.WebClient.DownloadString`.

Detección ya desplegada que cubre esta amenaza: **regla Wazuh 100120** (PowerShell ofuscado, 4104) y su equivalente Sigma `powershell_obfuscation_4104.yml`.

## Fuente de datos

| Canal (eventchannel) | EID | Campo clave | Por qué |
|---|---|---|---|
| `Microsoft-Windows-PowerShell/Operational` | **4104** | `win.eventdata.scriptBlockText` | Script Block Logging: reconstruye el scriptblock **ya desofuscado**. **Fuente primaria** del hunt. |
| `Security` | 4688 | `win.eventdata.commandLine` (+ `win.eventdata.newProcessName`) | Línea de comandos del proceso — captura el `-EncodedCommand` **antes** de decodificar. |
| `Microsoft-Windows-Sysmon/Operational` | 1 | `win.eventdata.image`, `win.eventdata.parentImage` (+ SHA256) | Linaje del proceso para correlar quién lanzó el PowerShell. |

**Matiz importante sobre `-EncodedCommand`:** el literal `-EncodedCommand` (o `-enc`) aparece en la **línea de comandos** (`commandLine` de 4688 / Sysmon 1), **no** dentro del `scriptBlockText` del 4104; en el 4104 lo que aparece es el contenido **ya decodificado**. Por eso `-EncodedCommand`/`-enc` se cazan en `commandLine` y el contenido desofuscado (`IEX`, `DownloadString`, `Net.WebClient`, `FromBase64String`…) se caza en `scriptBlockText`. La línea de comandos (`win.eventdata.commandLine`) es común a 4688 y a Sysmon EID 1 → campo preferido para cazar ejecución de forma agnóstica del sensor.

## La caza

### Wazuh (alerts.json, jq en el manager)

> Nota sobre el almacén: el archivado total (`logall`/`archives.json`) está **apagado**, pero la regla base **67027** alerta en **cada 4688** (nivel 3), así que `alerts.json` contiene de facto todo el histórico de creación de procesos de WIN11. Los 4104, al casar la regla 100120 (cuando son sospechosos) o la regla base de PowerShell, también llegan a `alerts.json`. Aun así, la caza **mira la telemetría cruda** (ver bloque Get-WinEvent), no solo lo que ya disparó una regla.

```bash
# 1) Universo del hunt: todos los scriptblocks 4104 del canal PowerShell/Operational.
#    (NO se filtra por 67027: esa regla dispara sobre 4688/Security, nunca sobre 4104.)
jq -c 'select(.data.win.system.eventID=="4104")
       | select(.data.win.system.channel=="Microsoft-Windows-PowerShell/Operational")
       | {ts:.timestamp, rule:.rule.id, sbt:.data.win.eventdata.scriptBlockText}' \
   /var/ossec/logs/alerts/alerts.json

# 2) Hunt real: 4104 cuyo scriptBlockText casa con el regex de cradles/ofuscacion.
#    Alineado con los keywords de la regla 100120 / sigma powershell_obfuscation_4104.yml.
jq -c 'select(.data.win.system.eventID=="4104")
       | select(.data.win.system.channel=="Microsoft-Windows-PowerShell/Operational")
       | select(.data.win.eventdata.scriptBlockText
            | test("FromBase64String|Invoke-Expression|\\bIEX\\b|DownloadString|DownloadData|Net\\.WebClient|Invoke-WebRequest|\\bIWR\\b"; "i"))
       | {ts:.timestamp, rule:.rule.id, lvl:.rule.level, sbt:.data.win.eventdata.scriptBlockText}' \
   /var/ossec/logs/alerts/alerts.json

# 3) Vista complementaria: el -EncodedCommand vive en la commandLine (4688 Security / Sysmon EID 1),
#    NO en el scriptBlockText. Se caza sobre commandLine (campo agnostico del sensor).
jq -c 'select(.data.win.system.eventID=="4688" or .data.win.system.eventID=="1")
       | select(.data.win.eventdata.commandLine
            | test("-enc(odedcommand)?\\b|FromBase64String|DownloadString|Net\\.WebClient"; "i"))
       | {ts:.timestamp, eid:.data.win.system.eventID, cl:.data.win.eventdata.commandLine}' \
   /var/ossec/logs/alerts/alerts.json

# 4) Confirmar que la deteccion ya disparo sobre el marcador malicioso.
jq -c 'select(.rule.id=="100120")
       | {ts:.timestamp, lvl:.rule.level, sbt:.data.win.eventdata.scriptBlockText}' \
   /var/ossec/logs/alerts/alerts.json
```

### Origen — logs crudos (PowerShell Direct, Get-WinEvent)

```powershell
# Desde el HOST Hyper-V hacia WIN11 via PowerShell Direct (red LAB-Net aislada).
# Se caza sobre el log CRUDO, no solo lo que ya disparo una regla en Wazuh.
Invoke-Command -VMName WIN11 -ScriptBlock {
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        Id      = 4104
    } |
    Where-Object {
        $_.Message -match 'FromBase64String|Invoke-Expression|\bIEX\b|DownloadString|DownloadData|Net\.WebClient|Invoke-WebRequest|\bIWR\b'
    } |
    Select-Object TimeCreated,
        @{ n='ScriptBlock'; e={ ($_.Message -split "`n")[0] } } |
    Format-Table -AutoSize -Wrap
}

# Complemento: el -EncodedCommand en la linea de comandos del proceso (Security 4688).
Invoke-Command -VMName WIN11 -ScriptBlock {
    Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688 } |
    Where-Object { $_.Message -match '(?i)-enc(odedcommand)?\b' } |
    Select-Object TimeCreated, @{ n='Proc'; e={ ($_.Message -split "`n" | Select-String 'New Process Name') } }
}
```

### KQL (Sentinel / Defender XDR — equivalente teórico, no se ejecuta)

```kql
// El lab corre Wazuh; este KQL es "como se veria en un SIEM cloud". No se ejecuta.

// (A) Defender XDR Advanced Hunting — scriptblock 4104 ofuscado.
DeviceEvents
| where ActionType == "PowerShellCommand"
| extend Script = tostring(parse_json(AdditionalFields).ScriptBlockText)
| where Script matches regex @"(?i)(FromBase64String|Invoke-Expression|\bIEX\b|DownloadString|DownloadData|Net\.WebClient|Invoke-WebRequest|\bIWR\b)"
| project Timestamp, DeviceName, InitiatingProcessFileName, Indicador = Script

// (B) Defender XDR — el -EncodedCommand en la linea de comandos del proceso.
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "FromBase64String", "DownloadString", "Net.WebClient")
| project Timestamp, DeviceName, InitiatingProcessFileName, Indicador = ProcessCommandLine

// (C) Microsoft Sentinel — canal PowerShell/Operational via AMA (equivalente directo del 4104 de Wazuh).
Event
| where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| where RenderedDescription has_any (
    "FromBase64String","Invoke-Expression","IEX","DownloadString",
    "DownloadData","Net.WebClient","Invoke-WebRequest","-enc","-EncodedCommand")
| project TimeGenerated, Computer, RenderedDescription
| sort by TimeGenerated desc
```

## Hallazgos (datos REALES del lab)

Sobre el universo de scriptblocks **4104** del canal `PowerShell/Operational` en `alerts.json`, tras aplicar el regex de cradles/ofuscación:

| # | Origen | scriptBlockText (resumen) | Veredicto | Regla |
|---|---|---|---|---|
| 1 | Atacante simulado | `IEX "Write-Output 'SOC-DE-PS-MARKER'"` — decodificado de un `powershell -EncodedCommand <b64>` | **MALICIOSO** | **100120** (nivel 12) |
| 2..n | Admin (PS-Remoting) | `PSCopyFileToRemoteSession`, `CheckPSDriveSize`, `PSCopyToSessionHelper` — funciones autogeneradas por `Copy-Item -ToSession` al desplegar agentes | Known-good | base 4104 |
| resto | Admin (script) | Inventario de archivos `*.inf` de Windows | Known-good | base 4104 |

- El **único** scriptblock realmente malicioso es el marcador `SOC-DE-PS-MARKER` ejecutado vía `IEX` y entregado como `-EncodedCommand` Base64 → casó el regex y disparó la **regla 100120 (nivel 12)**. Confirmado en la evidencia de validación del Proyecto 3 (2026-06-14): `[OK] 4104` con el marcador + `[OK] 4688` con `-EncodedCommand` en la línea de comandos.
- El resto de coincidencias del regex (`IEX`/`DownloadString`-like) eran **actividad administrativa legítima**: las funciones internas de `Copy-Item -ToSession` (despliegue de agentes Wazuh por PS-Remoting) y el script de inventario `*.inf`. Lección: la mayoría del 4104 "sospechoso" era ruido del propio admin.

> Nota de método: el conteo exacto de eventos depende del estado de `alerts.json` en el momento de la caza; lo verificable y reproducible es el **único hallazgo malicioso** (`SOC-DE-PS-MARKER`) confirmado contra `evidence/test-results.md`. El resto se clasifica como known-good administrativo.

## Triage: known-good vs malicioso

1. **Decodifica antes de juzgar.** El payload llega en Base64 (`-EncodedCommand`, visible en `commandLine`/4688); el 4104 lo muestra ya en claro en `scriptBlockText`. El marcador `SOC-DE-PS-MARKER` dentro de un `IEX` es inequívocamente la simulación de ataque.
2. **Atribuye al contexto, no solo al keyword.** `PSCopyFileToRemoteSession` / `CheckPSDriveSize` / `PSCopyToSessionHelper` son funciones **autogeneradas por PowerShell** durante `Copy-Item -ToSession`. Aparecen siempre que el admin despliega por PS-Remoting → patrón conocido, no `IEX` adversario.
3. **Correla el linaje (Sysmon EID 1 `parentImage` / 4688 `newProcessName`).** El cradle malicioso parte de un `powershell.exe -enc ...` sin padre legítimo de gestión; el ruido admin nace de sesiones WinRM/`wsmprovhost.exe` esperadas en ventanas de despliegue.
4. **Establece baseline (known-good).** Catalogar los 3 helpers de `Copy-Item -ToSession` y el inventario `*.inf` como allowlist reduce los falsos positivos del regex de 100120.

## Outcome

- **Cobertura confirmada:** la **regla 100120** (PowerShell ofuscado, 4104, nivel 12) ya detecta el caso real — disparó sobre el cradle `IEX … SOC-DE-PS-MARKER`. No se requiere nueva detección de base.
- **Reducción de FP (afinado de 100120):** documentar como baseline known-good los cradles administrativos —`PSCopyFileToRemoteSession`, `CheckPSDriveSize`, `PSCopyToSessionHelper` (de `Copy-Item -ToSession`) y el inventario `*.inf`— para excluirlos vía regla hija de menor severidad o lista CDB (`<list>`), evitando ruido en cada despliegue de agentes por PS-Remoting.
- **Lección de metodología:** la caza miró la telemetría **cruda** (universo completo de 4104 vía Get-WinEvent y jq), no solo lo que ya había disparado una regla; así se valida que la cobertura existente captura la amenaza **y** se construye el baseline para sostener su precisión.
- **Mejora de visibilidad sugerida:** correlar 4104 con Sysmon EID 1 (`parentImage`/SHA256) y 4688 (`commandLine` con `-enc`) para enriquecer la alerta de 100120 con linaje del proceso, reforzando la separación admin vs adversario.
