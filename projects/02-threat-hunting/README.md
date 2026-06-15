# Proyecto 2 — Threat Hunting Case Study

> Campaña de **6 cacerías (hunts)** sobre un dominio Active Directory en un laboratorio aislado, mapeadas a **MITRE ATT&CK**, cazando sobre **telemetría cruda** (no solo alertas) con **Wazuh 4.13.1** + **Sysmon** + **Defender**.

**TL;DR para reclutadores (2 min):** monté un SIEM self-hosted, definí hipótesis de amenaza, las verifiqué contra logs reales de Windows (Security 4688/4769/4768, Sysmon, PowerShell Script Block, System 7045, Defender) y traduje cada hallazgo en cobertura de detección o hardening. Resultado: 6 técnicas ATT&CK cubiertas, 1 regla candidata nueva (7045) y varias lecciones de metodología (el mito del RC4, el EDR como pista de caza, baseline de known-good).

---

## El lab

Todo corre en **Hyper-V** sobre una red **LAB-Net AISLADA** (sin salida a Internet ni a la red de casa).

| Host | Rol | IP |
|------|-----|----|
| **DC01** | Windows Server 2025 — AD DS, KDC, DNS del dominio `corp.local` (NetBIOS `CORP`) | `10.10.10.10` |
| **WIN11** | Windows 11 Pro unido al dominio — endpoint con **Sysmon** + **Microsoft Defender** | `10.10.10.21` |
| **Wazuh Manager** | SIEM self-hosted **Wazuh 4.13.1** | `10.10.10.20` |

> Nota: el lab usa **Wazuh**, no Microsoft Sentinel. El KQL que aparece en algunos hunts es el equivalente **teórico** ("cómo se vería en un SIEM cloud" — tablas `SecurityEvent`, `DeviceProcessEvents`, `DeviceEvents`); **no se ejecuta**, el motor real es Wazuh.

### Telemetría ingerida (canales `eventchannel` de los agentes Wazuh)

| Canal | Eventos clave |
|-------|---------------|
| **Security** | `4688` (creación de proceso **con línea de comandos**), `4624`/`4625` (logon), `4768`/`4769` (Kerberos TGT/TGS), `4720` (alta de usuario) |
| **Microsoft-Windows-Sysmon/Operational** | `EID 1` (creación de proceso con **hash SHA256** + linaje `ParentImage`), `EID 3` (conexión de red), `EID 11` (FileCreate) |
| **Microsoft-Windows-PowerShell/Operational** | `4104` (Script Block Logging) |
| **System** | `7045` (instalación de servicio nuevo) |
| **Microsoft-Windows-Windows Defender/Operational** | `1116` (detección), `1117` (acción) |

---

## Metodología de caza

Cada hunt sigue el ciclo **Hipótesis → Hunt → Findings → Outcome**:

1. **Hipótesis** — una afirmación falsable sobre comportamiento adversario ("si alguien hace Kerberoasting contra una cuenta de servicio, veré un `4769` con cifrado RC4").
2. **Hunt** — consultas sobre los datos para confirmar o refutar.
3. **Findings** — lo que apareció (incluyendo *known-good* y falsos positivos).
4. **Outcome** — la decisión: cobertura de detección confirmada, regla candidata nueva, o recomendación de hardening.

**Principio rector:** *la caza mira la telemetría cruda, no solo lo que ya disparó una regla.* Una alerta inexistente no prueba ausencia de amenaza — prueba ausencia de regla. Por eso cada hunt baja al log original.

### Cómo se cazó (dos planos de datos)

- **(a) Alertas en el manager — `jq` sobre `alerts.json`.** El archivado total (`logall`/`archives.json`) está **APAGADO**. Pero la regla base de Wazuh `67027` alerta en **cada** `4688` (nivel 3), así que `alerts.json` contiene *de facto* **todo el histórico de creación de procesos de WIN11** — un dataset de caza completo sin necesidad de archivado.
- **(b) Logs CRUDOS en origen — `Get-WinEvent` vía PowerShell Direct.** Para confirmar lo que el SIEM pudo no haber normalizado, se consultan los canales directamente en DC01 / WIN11.

### Nombres de campo (decoder `windows_eventchannel` de Wazuh)

- `win.system.eventID`, `win.system.channel`
- `win.eventdata.*` con **primera letra en minúscula**: `serviceName`, `commandLine`, `image`, `newProcessName`, `scriptBlockText`, `ticketEncryptionType`, `targetUserName`, `logonType`, `preAuthType`, `imagePath`.
- **Excepción** — los eventos de Defender conservan **espacios** en los nombres: `"threat Name"`, `"action Name"`.

**Detalle de ingeniería de detección:** la imagen del proceso vive en `win.eventdata.newProcessName` (Security 4688) pero en `win.eventdata.image` (Sysmon EID 1). En cambio `win.eventdata.commandLine` es **común a ambos sensores** → es el campo preferido para cazar ejecución **agnóstico del sensor**.

---

## Los 6 hunts — matriz de cobertura ATT&CK

| ID | Hunt | Táctica ATT&CK | Técnica | Outcome |
|----|------|----------------|---------|---------|
| **[H1](hunts/H1-powershell-obfuscation.md)** | PowerShell ofuscado / cradles de ejecución | Execution (TA0002) · *Defense Evasion (TA0005)* | **T1059.001** PowerShell + **T1027** Obfuscated Files | Cobertura confirmada: la regla `100120` (4104, nivel 12) detecta el cradle real (`IEX SOC-DE-PS-MARKER` vía `-EncodedCommand`). Se propone afinado/allowlist de los helpers de `Copy-Item -ToSession` para reducir FP y enriquecer con linaje Sysmon EID 1 / 4688. |
| **[H2](hunts/H2-lolbin-ingress-transfer.md)** | Ingress Tool Transfer vía LOLBins (`certutil`/`bitsadmin`/`mshta`) | Command and Control (TA0011) | **T1105** Ingress Tool Transfer · *T1218.005 Mshta* | Cobertura confirmada: reglas `100150`/`100151`/`100152` casan sobre `commandLine` (agnóstico de sensor); la `100150` disparó en las **16** ejecuciones simuladas de `certutil`. Defensa en profundidad acreditada con bloqueo de Defender (1116/1117). Hardening: verificar/ampliar el `ProcessCreate` include de Sysmon para estos binarios. |
| **[H3](hunts/H3-defender-tamper.md)** | Evasión de defensas: tamper de Defender + el EDR como pista de caza | Defense Evasion (TA0005) | **T1562.001** Impair Defenses: Disable or Modify Tools | Cobertura de tamper (regla `100130` por `commandLine`, agnóstica de sensor) + el EDR alimentando el SIEM (1116/1117 vía `100160`/`100161`) operacionalizado como **pivote de caza**. Defensa en profundidad validada (`certutil` disparó 100150 **y** 100160/100161). |
| **[H4](hunts/H4-new-service-persistence.md)** | Persistencia: servicios nuevos (`7045`) | Persistence / Privilege Escalation | **T1543.003** Create or Modify System Process: Windows Service | El hunt confirma **2× `7045` benignos** (reinstalación de Sysmon) y propone la regla candidata **`100170`** para 7045 con `imagePath` fuera de rutas de sistema o binario sin firmar. Ciclo *hunt → detección*. |
| **[H5](hunts/H5-kerberoasting.md)** | Kerberoasting (honeypot `svc_sql`) y el mito del RC4 | Credential Access | **T1558.003** Kerberoasting | Detección **determinística** vía honeypot de identidad `svc_sql` (regla `100110`, **agnóstica del cifrado**) que cubre el hueco de la firma clásica RC4 `0x17` (regla `100111`), evadida porque el KDC de WS2025 negoció **AES256 (`0x12`)**. Hardening: AES-only / gMSA en cuentas de servicio reales. |
| **[H6](hunts/H6-asrep-roasting.md)** | Cuentas AS-REP roastables (config hunt) | Credential Access | **T1558.004** AS-REP Roasting | Hunt de **configuración** en DC01: halla **1 cuenta roastable real** (señuelo `a.garcia` con `DONT_REQ_PREAUTH`) **antes de cualquier ataque**. Detección reactiva ya cubierta por la regla `100140` (4768 `preAuthType 0`), armada y sin disparos. |

> *Las detecciones referenciadas (reglas `1001xx`) viven en el **Proyecto 3 — Detection Engineering**. Este proyecto es la fase de **caza** que las valida, descubre sus huecos y propone las nuevas.*

### Señuelos (honeypots de identidad) en AD

| Cuenta | Trampa | Hunt |
|--------|--------|------|
| `svc_sql` | SPN `MSSQLSvc/sql01.corp.local:1433`, `msDS-SupportedEncryptionTypes=23` (RC4 habilitado), password débil `Summer2024!` | Kerberoasting (H5) |
| `a.garcia` | `DoesNotRequirePreAuth=True` | AS-REP Roasting (H6) |

---

## Hallazgos transversales

1. **La mayoría del "ruido sospechoso" era actividad de administración.** Servicios nuevos, ejecuciones de LOLBins y cradles de PowerShell resultaron, en su mayoría, ser legítimos. La caza sin **baseline de known-good** genera ansiedad, no señal: documentar lo benigno es parte del entregable.
2. **El mito del RC4 en Kerberoasting.** La firma clásica de Kerberoasting (`4769` con cifrado RC4 `0x17`) **no disparó**: el KDC de **Server 2025** negoció **AES256 (`0x12`)**. Lección: la detección por **identidad** (honeypot `svc_sql`, agnóstica del cifrado) supera a la detección por **cifrado**.
3. **Caza proactiva de configuración, antes de la explotación.** AS-REP roasting se cazó como un *config hunt* en el DC: encontrar la cuenta `DONT_REQ_PREAUTH` antes de que nadie la ataque vale más que detectar el ataque después.
4. **El EDR como pista de caza, no como punto final.** Las detecciones de Defender (`1116`/`1117`), reenviadas al SIEM, se usan como **pivote**: un bloqueo de Defender es una invitación a cazar alrededor de ese host/proceso, no el fin de la historia.
5. **El ciclo `hunt → detección`.** El hunt de servicios nuevos (`7045`) no encontró maldad, pero sí expuso un hueco de cobertura → de ahí nace la regla candidata `100170`. Cazar produce detecciones nuevas.

---

## Estructura de carpetas

```
projects/02-threat-hunting/
├── README.md            # este documento
├── hunts/               # un .md por hunt (H1–H6): hipótesis → hunt → findings → outcome
│   ├── H1-powershell-obfuscation.md
│   ├── H2-lolbin-ingress-transfer.md
│   ├── H3-defender-tamper.md
│   ├── H4-new-service-persistence.md
│   ├── H5-kerberoasting.md
│   └── H6-asrep-roasting.md
├── queries/             # consultas reutilizables: jq sobre alerts.json + Get-WinEvent (PowerShell) + KQL teórico
└── evidence/            # capturas y extractos de log que respaldan cada finding
```

---

## Qué demuestra este proyecto

- **Threat hunting estructurado y falsable** — ciclo Hipótesis → Hunt → Findings → Outcome sobre amenazas reales de Active Directory, mapeado a MITRE ATT&CK.
- **Cazar la telemetría cruda, no solo las alertas** — `jq` sobre `alerts.json` en el manager **y** `Get-WinEvent` en origen; entender que la ausencia de alerta no es ausencia de amenaza.
- **Dominio del dato de Windows/AD** — Security (4688/4769/4768), Sysmon (1/3/11), PowerShell 4104, System 7045 y Defender (1116/1117); y el matiz de campos del decoder de Wazuh (`commandLine` agnóstico vs `image`/`newProcessName`).
- **El puente hunt → detection engineering** — cada hunt termina en una decisión accionable: confirmar cobertura, proponer regla nueva (`100170`) o recomendar hardening (AES-only/gMSA, includes de Sysmon).
- **Criterio sobre lo nuevo, no solo lo memorizado** — el mito del RC4 desmontado en Server 2025: la detección por identidad (honeypot) gana a la detección por firma de cifrado.
- **SIEM self-hosted operado de punta a punta** — Wazuh 4.13.1 con agentes Windows, decoders, reglas y señuelos de identidad en un lab AD aislado y reproducible.
