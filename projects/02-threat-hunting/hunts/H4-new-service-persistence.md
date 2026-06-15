# Hunt H4 — Persistencia: servicios nuevos (7045)

> **Persistence / Privilege Escalation** · ATT&CK **T1543.003** (Create or Modify System Process: Windows Service).

## Hipotesis

Un atacante con privilegios administrativos instala un servicio Windows para **persistir** entre reinicios y/o **ejecutar codigo como SYSTEM**. Sospechamos que la creacion de un servicio nuevo en WIN11 (10.10.10.21) puede usarse para anclar un binario malicioso (ruta en `%TEMP%`, binario sin firmar o con nombre aleatorio). Cazamos TODOS los servicios recien instalados y separamos el ruido legitimo del operativo del lab mediante triage.

## Tecnica ATT&CK

**T1543.003 — Create or Modify System Process: Windows Service** (tacticas: Persistence, Privilege Escalation). El atacante registra un nuevo servicio (via `sc.exe`, `New-Service`, API `CreateServiceW` o escritura directa en `HKLM\SYSTEM\CurrentControlSet\Services`). El Service Control Manager (SCM) lo arranca en el contexto de la cuenta configurada —normalmente `LocalSystem`— lo que otorga ejecucion de alto privilegio y supervivencia al reinicio. Cada instalacion genera un **System EID 7045** ("A new service was installed") emitido por el SCM, con `ServiceName`, `ImagePath`, `ServiceType`, `StartType` y `AccountName`.

## Fuente de datos

- **Canal `System`, EID 7045** — fuente primaria; emite `serviceName` e `imagePath` (decoder `windows_eventchannel` de Wazuh) en cada instalacion de servicio. Es la senal canonica de T1543.003 y se ingiere via eventchannel en el agente Wazuh de WIN11.
- **Sysmon EID 1 / Security 4688** — telemetria de proceso de soporte: `commandLine` agnostico del sensor para correlacionar el *como* se instalo el servicio (p. ej. `sc.exe create`, `New-Service`), mas hash SHA256 y linaje (`parentImage`) desde Sysmon. La ruta de la imagen difiere por sensor (`newProcessName` en 4688, `image` en Sysmon EID 1), por eso correlacionamos por `commandLine`, que es comun a ambos.

Nota de metodologia: el hunt mira la telemetria **cruda**, no solo lo que ya disparo una regla. No existe aun deteccion para 7045, asi que el valor esta en revisar el canal `System` directamente (en alerts.json gracias a la regla base 67027, y en origen via Get-WinEvent).

## La caza

### Wazuh (alerts.json, jq en el manager)

```bash
# 1) Todos los servicios nuevos (7045): nombre + ruta del binario
jq -r 'select(.data.win.system.eventID=="7045")
  | [.timestamp,
     .data.win.eventdata.serviceName,
     .data.win.eventdata.imagePath]
  | @tsv' /var/ossec/logs/alerts/alerts.json

# 2) Filtro de senal roja: imagePath sospechoso (TEMP/AppData/ProgramData,
#    perfiles de usuario o Public; fuera de C:\Windows | C:\Program Files)
jq -r 'select(.data.win.system.eventID=="7045")
  | select(.data.win.eventdata.imagePath
      | ascii_downcase
      | test("\\\\temp\\\\|\\\\appdata\\\\|\\\\programdata\\\\|\\\\users\\\\|\\\\public\\\\"))
  | [.timestamp, .data.win.eventdata.serviceName, .data.win.eventdata.imagePath]
  | @tsv' /var/ossec/logs/alerts/alerts.json

# 3) Correlacion: linea de comandos que CREO el servicio (4688 + Sysmon EID 1)
#    cerca de la ventana del 7045 — campo commandLine agnostico del sensor
jq -r 'select(.data.win.system.eventID=="4688" or .data.win.system.eventID=="1")
  | select(.data.win.eventdata.commandLine
      | ascii_downcase
      | test("sc(\\.exe)?\\s+create|new-service|create.?service"))
  | [.timestamp, .data.win.system.eventID, .data.win.eventdata.commandLine]
  | @tsv' /var/ossec/logs/alerts/alerts.json
```

Notas de sintaxis (verificadas):
- `win.system.eventID` se almacena como **string** en Wazuh, por eso las comparaciones usan comillas (`=="7045"`). Correcto.
- En el regex de jq, `\\\\` en la cadena JSON se reduce a `\\`, que el motor regex interpreta como un backslash literal; asi `\\temp\\` casa con `\temp\` de una ruta Windows. Correcto.
- Query #3 usa solo `commandLine` (comun a 4688 y Sysmon EID 1); NO se referencia `newProcessName` ni `image`, evitando el desajuste de campo por sensor. Correcto.

### Origen — logs crudos (PowerShell Direct, Get-WinEvent)

```powershell
# Sobre WIN11 (10.10.10.21) via PowerShell Direct desde el host Hyper-V.
# Lee el canal System crudo: TODOS los 7045, no solo lo que disparo una regla.
Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045 } |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    [pscustomobject]@{
      Time    = $_.TimeCreated
      Service = ($x.Event.EventData.Data | Where-Object Name -eq 'ServiceName').'#text'
      Image   = ($x.Event.EventData.Data | Where-Object Name -eq 'ImagePath').'#text'
      Account = ($x.Event.EventData.Data | Where-Object Name -eq 'AccountName').'#text'
      Type    = ($x.Event.EventData.Data | Where-Object Name -eq 'StartType').'#text'
    }
  } | Sort-Object Time | Format-Table -AutoSize

# Validacion de firma del binario del servicio (descartar known-good firmado)
Get-AuthenticodeSignature 'C:\WINDOWS\Sysmon64.exe' |
  Select-Object Status, @{n='Signer';e={$_.SignerCertificate.Subject}}
```

> Nota: en el XML crudo `StartType` aparece como valor numerico/textual del SCM (p. ej. `auto start`, `demand start`); para triage interesa sobre todo el par `ServiceName` + `ImagePath` + `AccountName`.

### KQL (Sentinel / Defender XDR — equivalente)

```kql
// Equivalente cloud — no se ejecuta en el lab (corre Wazuh). Solo referencia.
// A) System 7045 -> tabla DeviceEvents (ActionType "ServiceInstalled")
DeviceEvents
| where ActionType == "ServiceInstalled"            // origen: System EID 7045
| extend Svc = tostring(parse_json(AdditionalFields).ServiceName),
         ImagePath = tostring(parse_json(AdditionalFields).ImagePath)
| where ImagePath has_any ("\\Temp\\","\\AppData\\","\\ProgramData\\","\\Users\\","\\Public\\")
| project Timestamp, DeviceName, Svc, ImagePath, InitiatingProcessAccountName

// B) Como se creo el servicio (proceso que invoco sc.exe / New-Service)
DeviceProcessEvents
| where ProcessCommandLine has_any ("sc create","sc.exe create","New-Service")
| project Timestamp, DeviceName, AccountName,
          ProcessCommandLine, InitiatingProcessFileName
```

## Hallazgos (datos REALES del lab)

El hunt sobre `alerts.json` devuelve **2 eventos 7045 en WIN11**, ambos a las **14:23:40**:

| Hora | serviceName | imagePath | Triage |
|------|-------------|-----------|--------|
| 14:23:40 | `Sysmon64` | `C:\WINDOWS\Sysmon64.exe` | BENIGNO |
| 14:23:40 | `SysmonDrv` | `C:\WINDOWS\SysmonDrv.sys` | BENIGNO |

Ambos servicios corresponden a la **reinstalacion de nuestro propio sensor Sysmon**, parte de la operacion del lab. El filtro de senal roja (query jq #2: `imagePath` en `%TEMP%`/`AppData`/`ProgramData`/`Users`/`Public`) devuelve **cero resultados**. No hay servicios maliciosos.

## Triage: known-good vs malicioso

Como analista, separo el ruido legitimo de la amenaza con tres ejes:

1. **Ruta (`imagePath`)** — `C:\WINDOWS\` y `C:\Program Files\` = rutas de sistema esperadas. La senal roja seria `%TEMP%`, `AppData`, `ProgramData`, perfiles de usuario o un binario con **nombre aleatorio**.
2. **Firma** — `Get-AuthenticodeSignature` sobre el binario del servicio: `Sysmon64.exe` esta firmado por Microsoft (Sysinternals). Un binario **sin firmar o con firma invalida** instalado como servicio es altamente sospechoso.
3. **Contexto temporal y de operacion** — los 2 eventos caen exactamente cuando reinstalamos el sensor; coinciden con una actividad de lab conocida y documentada. Mantener un **baseline de servicios conocidos** (nombre + ruta + firmante) convierte este triage en una comparacion contra lista blanca.

Veredicto: **BENIGNO** — reinstalacion legitima de Sysmon. El hunt confirma su propio valor: 7045 saca a la luz TODOS los servicios nuevos, incluidos los legitimos; el discernimiento esta en el triage.

## Outcome

**No existe regla Wazuh para 7045 todavia** -> este hunt genera una **regla candidata** (ciclo hunt -> deteccion):

- **Nueva deteccion propuesta** (siguiente ID libre de la serie `1001xx`, p. ej. **100170**): alertar en `eventID 7045` cuando `imagePath` resida en `%TEMP%`, `AppData`, `ProgramData`, perfiles de usuario o `Public` —o cuando el binario no este firmado/ruta sin whitelistear. Nivel alto (10-12), tactica Persistence (T1543.003). Se complementaria con las LOLBin existentes (100150/151/152) y el tamper de Defender (100130) para cubrir el flujo de instalacion.
- **Baseline / hardening** — mantener una whitelist de servicios conocidos (nombre + ruta + firmante) en el lab; los 2 servicios Sysmon (`Sysmon64` / `SysmonDrv`, ambos en `C:\WINDOWS\`) entran en el baseline como known-good para suprimir su ruido en futuras cazas.
- **Cobertura adicional** — emparejar la deteccion 7045 con la correlacion de `commandLine` (query jq #3) para capturar el *vector* de instalacion (`sc.exe create` / `New-Service`), no solo el resultado.
