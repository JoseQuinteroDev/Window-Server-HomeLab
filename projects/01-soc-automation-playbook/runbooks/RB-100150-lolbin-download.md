# 🛠️ Runbook RB-100150 — Descarga via LOLBin (certutil/bitsadmin/mshta)

> **Regla(s) Wazuh:** 100150 / 100151 / 100152 · **ATT&CK:** T1105 Ingress Tool Transfer (Command and Control) · **Severidad:** Media-Alta (nivel 10)

## 1. Disparo

La alerta salta cuando el `commandLine` de un proceso casa con un patron de descarga via binario legitimo del sistema (LOLBin):

- **100150** — `certutil` + (`-urlcache` | `/urlcache` | `-verifyctl` | `-split`).
- **100151** — `bitsadmin /transfer`.
- **100152** — `mshta` + `http`.

Matiz de Detection Engineering: el `include` de Sysmon del lab **no listaba `certutil`**, asi que ese evento no llego por Sysmon EID 1 (campo `image`) sino por **Security 4688** (imagen en `newProcessName`). Por eso las reglas matchean contra `commandLine` —campo comun a 4688 y Sysmon EID 1— y **no** contra `image`. Cualquier endpoint con la base 67027 (alerta en cada 4688) alimenta esta deteccion aunque Sysmon no instrumente el binario. Consecuencia practica para el triage: para `certutil` es probable que **no** existan Sysmon EID 1/EID 3; el **4688** es la fuente autoritativa. Para `bitsadmin`/`mshta`, revisa si Sysmon si los instrumenta antes de dar por vacio el linaje.

## 2. Triage inicial (objetivo: TP/FP en < 5 min)

Checklist en orden:

1. **¿Hay URL/destino remoto en el `commandLine`?** `certutil -urlcache` o `mshta` apuntando a una URL `http(s)://` externa = **rojo**. Sin URL (p.ej. `certutil -split` local, `certutil -decode` de un fichero local) baja la prioridad pero **no** lo cierra.
2. **¿Que cuenta y que host?** Cruzar con la BASELINE de known-good del Proyecto 2: la mayor parte del "ruido" previo era **actividad de ADMIN** (`CORP\Administrator`: PS-remoting, reinstalacion de Sysmon). Un LOLBin de descarga ejecutado por `j.perez`/`m.lopez`/`helpdesk` en WIN11 (10.10.10.21) **no** es known-good → TP probable.
3. **¿Defender disparo en paralelo?** Buscar **100160 (EID 1116, deteccion)** y **100161 (EID 1117, accion)** en la misma ventana y mismo `agent.name`. En el lab, el `certutil` fue detectado+bloqueado como **Trojan:Win32/Ceprolad.A** → defensa en profundidad y confirmacion fuerte de TP.
4. **Cuidado con binarios de uso comun:** Windows usa mucho `rundll32`; aqui el alcance es certutil/bitsadmin/mshta, pero si aparece linaje con `rundll32` benigno no lo cuentes como IoC sin URL/conexion confirmada.

**FP tipico:** `certutil` ejecutado por `CORP\Administrator` en tareas administrativas conocidas (decodificar/hashear un fichero local, sin URL). **TP tipico:** descarga desde URL externa por cuenta de usuario, especialmente si correla con 100160/100161.

## 3. Enriquecimiento

**Local en el SIEM (jq sobre `/var/ossec/logs/alerts/alerts.json`):**

```bash
# Eventos LOLBin de las 3 reglas, con commandLine y usuario
jq -r 'select(.rule.id=="100150" or .rule.id=="100151" or .rule.id=="100152")
  | [.timestamp, .agent.name, .rule.id, .data.win.eventdata.commandLine] | @tsv' \
  /var/ossec/logs/alerts/alerts.json

# ¿Defender correlaciono en el mismo host? (deteccion 1116 / accion 1117)
jq -r 'select(.rule.id=="100160" or .rule.id=="100161")
  | [.timestamp, .agent.name, .data.win.eventdata."threat Name", .data.win.eventdata."action Name"] | @tsv' \
  /var/ossec/logs/alerts/alerts.json
```

**Local en el endpoint (PowerShell Direct desde el host, sin red):**

```powershell
# Crudo de la creacion de proceso (Security 4688): linea de comandos + proceso padre.
# Fuente AUTORITATIVA para certutil (Sysmon no lo instrumenta en este lab).
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" -MaxEvents 50 |
  Where-Object { $_.Message -match 'certutil|bitsadmin|mshta' } |
  Select-Object TimeCreated, Message

# Linaje y hash del proceso (Sysmon EID 1): padre + SHA256.
# Util sobre todo para bitsadmin/mshta; para certutil puede venir vacio.
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1]]" |
  Where-Object { $_.Message -match 'certutil|bitsadmin|mshta' } |
  Select-Object TimeCreated, Message -First 20

# Conexiones de red salientes del proceso (Sysmon EID 3): destino real de la descarga
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=3]]" |
  Where-Object { $_.Message -match 'certutil|bitsadmin|mshta' } |
  Select-Object TimeCreated, Message

# Estado del EDR y deteccion concreta
Get-MpThreat
Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled, AntivirusSignatureVersion
```

**Quien es la cuenta (AD, PS Direct contra DC01 = 10.10.10.10):**

```powershell
Get-ADUser -Identity j.perez -Properties MemberOf, LastLogonDate, Enabled
```

**Enriquecimiento externo (CONCEPTUAL — el lab esta AISLADO, sin internet):** en un SOC real se haria IoC lookup de la URL/dominio/IP del `commandLine` y del SHA256 del fichero descargado contra **VirusTotal / AbuseIPDB / OTX** mediante plantilla de lookup. Aqui se documenta el IoC para hacerlo fuera de banda.

## 4. Investigacion

Preguntas a responder y pivotes:

- **Linaje:** ¿quien lanzo el LOLBin? Proceso padre en **Security 4688** (autoritativo para certutil) y `parentImage` en Sysmon EID 1 (cuando exista). Si el padre es `winword.exe`/`outlook.exe`/`mshta.exe` → cadena de entrega (phishing/macro).
- **Destino:** ¿que URL/IP aparece en el `commandLine`? ¿La confirma Sysmon EID 3 (si el binario esta instrumentado)? ¿El fichero llego a disco? Calcular SHA256 para correlar.
- **Usuario:** ¿cuenta de usuario o ADMIN? ¿pertenencia a grupos privilegiados (`Get-ADUser -Properties MemberOf`)? ¿coherente con su rol?
- **Temporalidad:** ¿hora del 4688/EID 1 vs. 1116/1117 de Defender? Reconstruir la secuencia descarga → deteccion → bloqueo.
- **Alcance:** ¿se **ejecuto** el payload descargado, o Defender lo bloqueo antes (1117)? ¿solo WIN11 o aparece el mismo `commandLine`/hash en otros agentes? (repetir el jq y agrupar por `agent.name`).
- **Historico:** revisar 4688 previos del mismo proceso/cuenta en `alerts.json` (regla base 67027) para descartar actividad recurrente legitima.

## 5. Respuesta

Proporcional a nivel 10 (Media-Alta), escalando si correla con 100160/100161:

- **Contencion:**
  - Si Defender ya bloqueo+cuarentena (1117 / Trojan:Win32/Ceprolad.A) → confirmar cuarentena con `Get-MpThreat` y **conservar** el fichero como evidencia.
  - **Aislar WIN11** (en el lab: desconectar el adaptador de la VM via Hyper-V) si hay indicio de que el **payload se ejecuto** (proceso hijo del fichero descargado, EID 3 hacia el C2, persistencia).
  - **Bloquear la URL/IP** del `commandLine` (en SOC real: en proxy/firewall/EDR; en el lab queda como IoC documentado, red ya aislada).
- **Erradicacion:** poner en **cuarentena/eliminar** el fichero descargado; revisar persistencia (servicios nuevos 7045 → candidata 100170, tareas programadas, Run keys).
- **Escalado / handoff a IR:** si se confirma ejecucion del payload o movimiento posterior, abrir incidente y entregar a **IR completo (PICERL, Proyecto 4)**. Este runbook llega hasta la respuesta inicial.

## 6. Documentacion

Registrar en el caso:

- **Identificacion:** `rule.id` (100150/151/152), `timestamp`, `agent.name` (host), cuenta (`targetUserName`/usuario del 4688).
- **Evidencia tecnica:** `commandLine` completo, `newProcessName` (4688) o `image` (EID 1), proceso padre, **SHA256** del binario LOLBin y del fichero descargado.
- **IoCs:** URL/dominio/IP del `commandLine`, SHA256 del payload, nombre de deteccion de Defender (`threat Name` = Trojan:Win32/Ceprolad.A) y `action Name`.
- **Correlacion:** IDs de alertas relacionadas (100160/100161) y secuencia temporal.
- **Decision:** TP/FP, justificacion contra la baseline de known-good, acciones tomadas (cuarentena/aislamiento/bloqueo) y si se escala a IR.

## 7. Automatizacion aplicable

Las alertas que correlan a nivel ≥12 (p.ej. la deteccion de Defender 100160) ya disparan la **Active Response lado-manager** que abre caso automaticamente con enriquecimiento de solo-lectura. Para este runbook se puede automatizar la recoleccion inicial (extraccion del `commandLine`/URL, lanzar `Get-MpThreat` y el jq de correlacion con 100160/100161) como script de enriquecimiento adjunto al ticket; el aislamiento del host y el bloqueo de URL se dejan como accion manual aprobada por el analista (no se automatiza contencion destructiva).