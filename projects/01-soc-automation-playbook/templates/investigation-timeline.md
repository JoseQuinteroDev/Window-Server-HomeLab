# Plantilla — Timeline de investigacion

Documento de trabajo para reconstruir cronologicamente un incidente en el lab `corp.local` (LAB-Net aislada). El analista anota cada evento a medida que lo confirma, citando la **fuente** (regla Wazuh, EID, query) y la **observacion** factual, separada de la **accion**. El objetivo es llegar a la respuesta inicial y al handoff a IR (PICERL se profundiza en el Proyecto 4).

## Cabecera del caso

| Campo | Valor |
|---|---|
| Caso ID | `<CASO-AAAAMMDD-NN>` (auto si lo abrio la Active Response) |
| Analista | `<nombre>` |
| Fecha apertura | `<AAAA-MM-DD HH:MM TZ>` |
| Disparador | `<regla Wazuh / alerta que origino el caso>` |
| Host(s) | WIN11 (10.10.10.21) / DC01 (10.10.10.10) / manager Wazuh (10.10.10.20) |
| Severidad inicial | `<nivel Wazuh>` |
| Estado | Abierto / En triage / Contenido / Handoff IR / Cerrado |
| Tecnica(s) ATT&CK | `<Txxxx>` |

> **Convencion de notas**: una fila por evento atomico. `Hora` en hora del log (no la del analista). Si la fuente y el log discrepan, anotar ambas. La columna `Accion` registra lo que HIZO el analista, no lo que recomienda; las recomendaciones van en Hallazgos.

## Timeline cronologico

| Hora (log) | Evento | Fuente | Observacion | Accion |
|---|---|---|---|---|
| `HH:MM:SS` | `<que paso>` | `<regla 1001xx / EID / query>` | `<dato crudo confirmado>` | `<que hizo el analista>` |

### Ejemplo resuelto — `certutil` (defensa en profundidad)

Secuencia real del lab: una descarga via LOLBin `certutil` disparo la deteccion de comportamiento (100150 sobre 4688) **y** simultaneamente Microsoft Defender la detecto y bloqueo (100160/100161). El analista reconstruye que ambas alertas son el **mismo evento** visto por dos capas.

| Hora (log) | Evento | Fuente | Observacion | Accion |
|---|---|---|---|---|
| 14:02:11 | Proceso `certutil.exe` ejecutado en WIN11 con flag de descarga | Wazuh 100150 (nivel 10) sobre Security 4688; T1105 | `win.eventdata.commandLine` contiene `certutil -urlcache -split -f http://...`; `win.eventdata.newProcessName` = `C:\Windows\System32\certutil.exe` | Abro caso; marco WIN11 como host afectado |
| 14:02:11 | Active Response lado-manager abre caso automatico (nivel >=12 al correlar) | Wazuh AR (apertura de ticket, solo-lectura) | Ticket creado con las alertas asociadas | Confirmo que el caso ya estaba abierto; evito duplicar |
| 14:02:12 | Defender detecta el binario/payload descargado | Wazuh 100160 (nivel 12); canal `Microsoft-Windows-Windows Defender/Operational` EID 1116 | `win.eventdata."threat Name"` = `Trojan:Win32/Ceprolad.A` | Correlaciono por host+ventana temporal: mismo evento que 100150 |
| 14:02:12 | Defender ejecuta accion de remediacion | Wazuh 100161 (nivel 10); canal Defender EID 1117 | `win.eventdata."action Name"` = bloqueo/cuarentena | Concluyo **defensa en profundidad**: el comportamiento se detecto Y el EDR lo bloqueo |
| 14:05:30 | Enriquecimiento de linaje de proceso | Sysmon EID 1 (parentImage + SHA256) via Get-WinEvent | parentImage del `certutil` = `<proceso padre>`; SHA256 del binario descargado = `<hash>` | Uso el padre como pivote de caza; anoto hash como IoC |
| 14:09:00 | Verificacion en endpoint | `Get-MpThreat` / `Get-MpComputerStatus` (PowerShell Direct) | Amenaza listada como remediada; RTP activo | Confirmo que no quedo ejecucion activa del payload |
| 14:12:00 | Pivote: el EDR como pista de caza | Historico 4688 (regla base 67027 en `alerts.json`) | Busco otros 4688 del mismo padre/host alrededor de la ventana | Determino alcance; no aparecen otros hosts (red aislada) |
| 14:20:00 | Triage de baseline | Hallazgos Proyecto 2 (known-good) | El padre/contexto **no** coincide con actividad de ADMIN conocida (PS-remoting, reinstalacion de Sysmon) | Descarto falso positivo de admin; mantengo como verdadero positivo |

### Queries de soporte (ejecutables)

Sobre el SIEM (manager Wazuh), `alerts.json`:

```bash
# Todas las alertas del caso certutil (LOLBin + Defender) por regla
jq -c 'select(.rule.id=="100150" or .rule.id=="100160" or .rule.id=="100161")
  | {ts:.timestamp, rule:.rule.id, lvl:.rule.level,
     cmd:.data.win.eventdata.commandLine,
     img:.data.win.eventdata.newProcessName,
     threat:.data.win.eventdata."threat Name",
     action:.data.win.eventdata."action Name"}' \
  /var/ossec/logs/alerts/alerts.json
```

```bash
# Linaje: historico de 4688 (regla base 67027) en WIN11, ventana del incidente
jq -c 'select(.rule.id=="67027" and (.data.win.eventdata.newProcessName // ""
  | test("certutil|powershell|mshta|bitsadmin"; "i")))
  | {ts:.timestamp, proc:.data.win.eventdata.newProcessName,
     cmd:.data.win.eventdata.commandLine}' \
  /var/ossec/logs/alerts/alerts.json
```

En el endpoint WIN11 (PowerShell Direct desde el host):

```powershell
# Detecciones/acciones de Defender (1116/1117) en la ventana del incidente
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117
} | Select-Object TimeCreated, Id, Message | Format-List
```

```powershell
# Estado de amenaza y del motor antivirus
Get-MpThreat
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, AMServiceEnabled
```

```powershell
# Linaje de proceso via Sysmon EID 1 (parentImage + Hashes)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} | Where-Object { $_.Message -match 'certutil' } |
  Select-Object TimeCreated, Message | Format-List
```

## Indicadores de compromiso (IoCs)

| Tipo | Valor | Origen | Estado |
|---|---|---|---|
| Proceso/LOLBin | `certutil.exe` con `-urlcache`/`-split` | Wazuh 100150 / 4688 | Confirmado |
| Nombre de amenaza | `Trojan:Win32/Ceprolad.A` | Defender 1116 (`threat Name`) | Confirmado |
| Hash (SHA256) | `<hash del binario descargado>` | Sysmon EID 1 | `<a completar>` |
| URL/host C2 | `<http://... del commandLine>` | Wazuh 100150 (`commandLine`) | `<a completar>` |
| Proceso padre | `<parentImage>` | Sysmon EID 1 | `<a completar>` |

> **Enriquecimiento externo (CONCEPTUAL — lab aislado)**: en un SOC real, hash/URL/IP iran a VirusTotal, AbuseIPDB y OTX via plantilla de IoC lookup. Aqui el enriquecimiento **real** es LOCAL: AD (`Get-ADUser`, pertenencia a grupos), linaje de proceso Sysmon (parentImage + SHA256), historico de 4688 en `alerts.json`, `Get-MpThreat`/`Get-MpComputerStatus`, y el log crudo via `Get-WinEvent`.

## Hallazgos

| # | Hallazgo | Evidencia | Severidad | Recomendacion / handoff |
|---|---|---|---|---|
| 1 | Ejecucion de LOLBin `certutil` para descarga (T1105) | 100150 / 4688 (`commandLine`) | Alta | Verdadero positivo; pasar a IR para erradicacion |
| 2 | Defensa en profundidad: Defender detecto y bloqueo el payload | 100160/100161 (1116/1117) | Informativo | El endpoint contuvo la amenaza; confirmar que no hay reejecucion |
| 3 | El EDR (1116/1117) sirvio de pivote de caza | Pivote sobre 4688 historico | Medio | Mantener 1116/1117 como pista de caza en futuros casos |
| 4 | No coincide con baseline de ADMIN conocido | Hallazgos Proyecto 2 (known-good) | n/a | Descartado falso positivo; el ruido tipico era PS-remoting / reinstalacion de Sysmon |

### Conclusion y handoff a IR

- **Veredicto**: `<Verdadero positivo / Falso positivo / Benigno>`.
- **Contencion inicial aplicada**: `<p.ej. amenaza en cuarentena por Defender; sin reejecucion confirmada>`.
- **Pendiente para IR (PICERL — Proyecto 4)**: Contain/Eradicate/Recover sobre WIN11 y validacion de alcance en DC01.
- **Adjuntos**: este timeline, IoCs y queries ejecutadas.
