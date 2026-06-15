# Enriquecimiento de alertas

> Playbook de automatizacion SOC — Lab `corp.local` (Hyper-V, LAB-Net **aislada**, sin internet). SIEM Wazuh 4.13.1 (manager `10.10.10.20`). Endpoints: `DC01` (WS2025, `10.10.10.10`), `WIN11` (`10.10.10.21`, Sysmon + Defender). Operacion por **PowerShell Direct** desde el host.

El enriquecimiento es el paso entre la **alerta** (regla `1001xx` que dispara) y la **decision** (escalar a IR / cerrar como benigno). Su objetivo es responder tres preguntas antes de tocar el endpoint: **quien** (identidad/cuenta), **que** (proceso/linaje/hash) y **es conocido-bueno** (baseline vs. malicioso). En un lab aislado distinguimos dos planos: **enriquecimiento LOCAL** (real, ejecutable hoy) y **enriquecimiento EXTERNO** (conceptual, lo que se haria en un SOC con salida a internet, documentado como plantilla).

---

## 1. Enriquecimiento LOCAL (disponible en el lab)

Cinco fuentes locales, todas de **solo lectura** y seguras de ejecutar durante el triage.

### 1.1 Identidad — Active Directory (`Get-ADUser`, pertenencia a grupos)

Aplica a toda alerta con una cuenta: Kerberoasting (`100110`/`100111`), AS-REP (`100140`), o cualquier `targetUserName`. Determina si la cuenta es **honeypot**, **usuario real**, **admin** o **cuenta de equipo**.

Sobre `DC01` por PowerShell Direct:

```powershell
# Enriquecer la cuenta objetivo de una alerta Kerberoasting/AS-REP
$u = 'svc_sql'   # o el targetUserName extraido de la alerta
Get-ADUser -Identity $u -Properties MemberOf, ServicePrincipalName, `
  msDS-SupportedEncryptionTypes, DoesNotRequirePreAuth, PasswordLastSet, `
  LastLogonDate, Enabled |
  Select-Object SamAccountName, Enabled, DoesNotRequirePreAuth, `
    @{n='SPN';e={$_.ServicePrincipalName}}, `
    @{n='EncTypes';e={$_.'msDS-SupportedEncryptionTypes'}}, `
    PasswordLastSet, LastLogonDate, `
    @{n='Grupos';e={($_.MemberOf | ForEach-Object{($_ -split ',')[0] -replace 'CN='}) -join ', '}}
```

Lectura del resultado:
- `svc_sql` con `SPN = MSSQLSvc/sql01.corp.local:1433` y `EncTypes = 23` (RC4 habilitado) -> es el **honeypot de Kerberoasting**. Cualquier TGS contra ella (`100110`) es malicioso por definicion: **escalar**.
- `a.garcia` con `DoesNotRequirePreAuth = True` -> es el **honeypot de AS-REP** (`100140`).
- Si la cuenta es `CORP\Administrator` o miembro de Domain Admins -> alta criticidad y candidato a baseline (ver 1.6: gran parte del "ruido" del Proyecto 2 era actividad de admin).

### 1.2 Linaje de proceso — Sysmon EID 1 (`parentImage` + hash SHA256)

Aplica a PowerShell ofuscado (`100120`), tamper de Defender (`100130`) y LOLBins (`100150`/`100151`/`100152`). Convierte un command-line aislado en una **cadena padre-hijo** con hash para pivotar.

Por jq sobre el log del manager — recupera el evento Sysmon de creacion de proceso correlacionado:

```bash
jq -r 'select(.rule.id=="100120" or .rule.id=="100130" or .rule.id=="100150"
        or .rule.id=="100151" or .rule.id=="100152")
  | select(.data.win.system.eventID=="1")
  | [.timestamp, .agent.name,
     .data.win.eventdata.parentImage,
     .data.win.eventdata.image,
     .data.win.eventdata.commandLine,
     .data.win.eventdata.hashes] | @tsv' \
  /var/ossec/logs/alerts/alerts.json
```

Sobre el endpoint (`WIN11`), linaje en vivo via Sysmon Operational:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 50 |
  Where-Object { $_.Message -match 'certutil|mshta|bitsadmin|powershell' } |
  ForEach-Object {
    $x=[xml]$_.ToXml(); $d=@{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }
    [pscustomobject]@{
      Hora=$_.TimeCreated; Imagen=$d.Image; Padre=$d.ParentImage
      Cmd=$d.CommandLine; SHA256=($d.Hashes -replace '.*SHA256=([0-9A-Fa-f]+).*','$1')
    }
  } | Format-List
```

Lectura: un `parentImage` legitimo (`explorer.exe`, sesion interactiva de admin) apunta a baseline; un padre anomalo (`winword.exe`, `w3wp.exe`, `outlook.exe` -> `powershell.exe`/`certutil.exe`) indica ejecucion derivada de un payload. El **SHA256** es el IoC que se lleva al lookup externo (seccion 2).

### 1.3 Historico de ejecucion — `4688` en `alerts.json`

La regla base `67027` alerta en **cada** `4688` (creacion de proceso). Eso da un historico consultable: cuantas veces se vio el binario/cuenta antes, primera/ultima aparicion -> **frecuencia = senal de baseline**.

```bash
# Cuantas veces y cuando se ha visto este binario por cuenta (4688)
jq -r 'select(.data.win.system.eventID=="4688")
  | select(.data.win.eventdata.newProcessName | test("certutil|mshta|bitsadmin|powershell"; "i"))
  | [.data.win.eventdata.newProcessName, .data.win.eventdata.subjectUserName] | @tsv' \
  /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn
```

```bash
# Primera y ultima vez que aparece un proceso concreto (perfil temporal)
jq -r 'select(.data.win.system.eventID=="4688")
  | select(.data.win.eventdata.newProcessName | test("certutil.exe"; "i"))
  | [.timestamp, .data.win.eventdata.subjectUserName,
     .data.win.eventdata.commandLine] | @tsv' \
  /var/ossec/logs/alerts/alerts.json | sort | head -1   # primera; cambia head -1 por tail -1 para la ultima
```

Lectura: un binario que aparece **decenas de veces** desde una cuenta de admin desde hace semanas es baseline (ruido); una **primera aparicion** correlacionada con la alerta es la senal real.

### 1.4 Estado del endpoint — `Get-MpThreat` / `Get-MpComputerStatus`

Imprescindible para confirmar la **defensa en profundidad** (hallazgo Proyecto 2: Defender detecto+bloqueo el `certutil` como `Trojan:Win32/Ceprolad.A`, EID 1116/1117). Ante `100150`/`100151`/`100152`/`100120`/`100160`/`100161`, confirma si Defender ya actuo.

Sobre el endpoint afectado (`WIN11`):

```powershell
# Amenazas detectadas (correlaciona con EID 1116/1117 -> reglas 100160/100161)
Get-MpThreat | Select-Object ThreatName, SeverityID, ProcessName, Resources, `
  @{n='Detectada';e={$_.InitialDetectionTime}}, `
  @{n='Accion';e={$_.ThreatStatusID}} | Format-List

# Postura de proteccion: si RealTime/Tamper estan OFF -> corrobora un 100130 (tamper)
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, `
  TamperProtected, AntispywareEnabled, IoavProtectionEnabled, `
  AMServiceEnabled, NISEnabled
```

Lectura: si `Get-MpThreat` lista `Trojan:Win32/Ceprolad.A` con accion de cuarentena -> el bloqueo (`100161`/EID 1117) **ya conteuvo** el LOLBin; baja la urgencia de contencion manual pero **no cierra el caso** (hay que erradicar el origen). Si una alerta `100130` coincide con `RealTimeProtectionEnabled=False` -> el tamper tuvo exito: maxima prioridad.

### 1.5 Log crudo — `Get-WinEvent`

Cuando el campo de la alerta no basta, ir al evento original en el canal del endpoint. Util para Defender (campos con espacio `threat Name`/`action Name`), Kerberos y servicios.

```powershell
# Detalle del evento Defender que disparo 100160/100161 (EID 1116/1117)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117
} -MaxEvents 5 | Format-List TimeCreated, Id, Message

# Detalle de un TGS sospechoso (4769) en el DC: cifrado y servicio solicitado
Get-WinEvent -ComputerName DC01 -FilterHashtable @{
  LogName='Security'; Id=4769
} -MaxEvents 20 |
  Where-Object { $_.Message -match 'svc_sql' -or $_.Message -match '0x17' } |
  Format-List TimeCreated, Message
```

Equivalente jq lado-manager para el TGS (campos Wazuh):

```bash
jq -r 'select(.data.win.system.eventID=="4769")
  | [.timestamp, .data.win.eventdata.targetUserName,
     .data.win.eventdata.ticketEncryptionType,
     .data.win.eventdata.ipAddress] | @tsv' \
  /var/ossec/logs/alerts/alerts.json
```

Recordar el **mito del RC4** (Proyecto 2): WS2025 negocia AES (`0x12`), por lo que la firma RC4 `0x17` de `100111` se evade facilmente. El log crudo confirma el `ticketEncryptionType` real; la deteccion robusta no es el cifrado sino el **honeypot** `svc_sql` (`100110`).

### 1.6 Pivote por baseline (known-good)

El hallazgo central del Proyecto 2: la mayoria del "ruido sospechoso" era **actividad de admin** (PS-remoting, reinstalacion de Sysmon). Antes de escalar, cruzar siempre contra el baseline:

```bash
# Es la cuenta origen un admin conocido? (filtra el ruido legitimo)
jq -r 'select(.rule.level>=10)
  | [.rule.id, .data.win.eventdata.subjectUserName // .data.win.eventdata.targetUserName, .agent.name]
  | @tsv' /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn
```

Si la cuenta es `CORP\Administrator` desde `WIN11` reinstalando Sysmon -> conocido-bueno -> cierre con nota. Si es una cuenta de usuario (`j.perez`/`m.lopez`) ejecutando `certutil -urlcache` -> anomalo -> escalar.

---

## 2. Enriquecimiento EXTERNO (conceptual — plantilla de IoC lookup)

El lab esta **aislado**: no hay salida a VirusTotal/AbuseIPDB/OTX/whois. Documentamos el procedimiento como **plantilla** para portarlo a un SOC con conectividad. Los IoCs salen del enriquecimiento local (SHA256 de Sysmon EID 1, IPs de `4769`, dominios de command-lines de LOLBin).

| IoC | Fuente externa | Que aporta a la decision |
|---|---|---|
| Hash SHA256 (de Sysmon `hashes`) | VirusTotal | Reputacion del binario, deteccion multi-AV, familia de malware |
| IP (`ipAddress` de `4769`, IP de descarga) | AbuseIPDB / VirusTotal | Reputacion, geolocalizacion, reportes de abuso |
| Hash / IP / dominio | OTX (AlienVault) | Asociacion a pulses/campanas y TTPs |
| Dominio / IP de descarga (LOLBin) | whois | Edad del dominio, registrante, hosting (dominio recien creado = sospechoso) |

Plantilla de IoC lookup (a rellenar durante el triage, hoy de forma manual/offline):

```text
=== IoC LOOKUP (plantilla SOC real) ===
Alerta / regla     : 100150  (LOLBin certutil)
Endpoint           : WIN11 (10.10.10.21)
IoC tipo           : SHA256
IoC valor          : <sha256 de Sysmon EID 1>
Linaje (padre->hijo): <parentImage> -> certutil.exe
--- Resultados externos (rellenar con conectividad) ---
VirusTotal         : __/__ detecciones  | familia: ______
AbuseIPDB (IP)     : score ___% | reportes: ___
OTX                : pulse(s): ______
whois (dominio)    : creado: ______ | registrante: ______
--- Decision ---
Veredicto          : [ ] Benigno  [ ] Sospechoso  [ ] Malicioso
Accion             : [ ] Cerrar  [ ] Escalar a IR
```

En este lab, el sustituto real de VirusTotal es **Defender local** (seccion 1.4): `Trojan:Win32/Ceprolad.A` es el "veredicto de reputacion" obtenido sin internet.

---

## 3. Como el enriquecimiento reduce ruido y acelera la decision

- **Reduce ruido (falsos positivos):** el cruce contra baseline (1.6) + AD (1.1) descarta la actividad de admin que dominaba el "ruido sospechoso" del Proyecto 2 (PS-remoting, reinstalacion de Sysmon). El historico de `4688` (1.3) separa lo recurrente (baseline) de la primera aparicion (senal).
- **Confirma severidad:** AD identifica honeypots (`svc_sql`, `a.garcia`) -> un `100110` deja de ser "una alerta mas" y pasa a malicioso determinista. `Get-MpComputerStatus` confirma si un `100130` realmente apago la proteccion.
- **Acelera la decision:** el linaje Sysmon (1.2) + `Get-MpThreat` (1.4) responden "que se ejecuto y si ya fue contenido" en una sola pasada, evitando idas y vueltas al endpoint. El SHA256 queda listo para el lookup externo sin re-investigar.
- **Prioriza la respuesta:** cuando Defender ya bloqueo (EID 1117 / `100161`), la urgencia de contencion baja y el foco pasa a erradicar el origen — handoff limpio a IR.

---

## 4. Integracion con la automatizacion (Wazuh Active Response)

La AR lado-manager abre **automaticamente un caso** ante alertas de **nivel >= 12** (apertura de ticket + enriquecimiento, accion segura y de solo-lectura). El playbook de enriquecimiento es exactamente lo que ese caso debe pre-rellenar: para cada alerta nivel >= 12 (`100110`, `100120`, `100130`, `100140`, `100160`) el caso adjunta cuenta+grupos (AD), linaje+SHA256 (Sysmon), historico `4688` y estado Defender, mas la plantilla de IoC lookup lista para completar. **No** usamos Logic Apps/Sentinel (esa seria la variante cloud).

## 5. Handoff a IR

El enriquecimiento llega hasta la **respuesta inicial**: alerta enriquecida + veredicto preliminar + indicadores de contencion ya aplicada (Defender). El IR completo (PICERL: Prepare/Identify/Contain/Eradicate/Recover/Lessons) se profundiza en el Proyecto 4; aqui se entrega el caso con identidad resuelta, linaje, hashes e historico para que la fase de Identify de IR arranque sin re-trabajo.
